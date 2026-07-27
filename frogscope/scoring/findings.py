"""Finding emission and de-duplication.

A finding is per (rule, asset), not per row — otherwise one Cloudflare-fronted
host produces the same finding thirteen times, once per alias port, and the feed
becomes unreadable.

Severity comes from the rule, not from the endpoint's score: a critical rule on
an otherwise unremarkable host must still be visible. The reopen-on-reobserve
behaviour follows frogy_web/ingest/store.py:upsert_finding.
"""

from __future__ import annotations

import json
import sqlite3
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC
from typing import Any

from .engine import Contribution, ScoreResult

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class Finding:
    dedup_key: str
    rule_id: str
    severity: str
    confidence: str
    title: str
    asset_kind: str
    asset_key: str
    why: str
    remediation: str
    evidence: dict[str, Any] = field(default_factory=dict)
    endpoints: list[str] = field(default_factory=list)
    endpoint_count: int = 0
    hosts: list[str] = field(default_factory=list)
    host_count: int = 0
    max_score: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "dedup_key": self.dedup_key,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "confidence": self.confidence,
            "title": self.title,
            "asset_kind": self.asset_kind,
            "asset_key": self.asset_key,
            "why": self.why,
            "remediation": self.remediation,
            "evidence": self.evidence,
            "endpoints": self.endpoints,
            "endpoint_count": self.endpoint_count,
            "hosts": self.hosts,
            "host_count": self.host_count,
            "max_score": self.max_score,
        }


def build_findings(scored: list[tuple[dict, ScoreResult]]) -> list[Finding]:
    """Collapse per-endpoint contributions into per (rule, host) findings."""
    grouped: dict[tuple[str, str], list[tuple[dict, Contribution, ScoreResult]]] = defaultdict(list)

    for record, result in scored:
        if result.excluded:
            continue
        for contribution in result.findings:
            grouped[(contribution.rule_id, record["host"])].append(
                (record, contribution, result))

    findings: list[Finding] = []
    for (rule_id, host), items in grouped.items():
        # Prefer the endpoint with the highest score as the representative, so
        # the `why` text and evidence come from the worst instance.
        record, contribution, result = max(items, key=lambda t: t[2].score)
        endpoints = sorted({r["endpoint_key"] for r, _c, _s in items})

        findings.append(Finding(
            dedup_key=f"{rule_id}:host:{host}",
            rule_id=rule_id,
            severity=contribution.severity,
            confidence=contribution.confidence,
            title=contribution.title,
            asset_kind="host",
            asset_key=host,
            why=contribution.why,
            remediation=contribution.remediation,
            evidence=contribution.evidence,
            endpoints=endpoints,
            endpoint_count=len(endpoints),
            hosts=[host],
            host_count=1,
            max_score=max(s.score for _r, _c, s in items),
        ))

    findings.sort(key=lambda f: (SEVERITY_RANK.get(f.severity, 9), -f.max_score,
                                 f.rule_id, f.asset_key))
    return findings


def upsert_findings(conn: sqlite3.Connection, project_id: int, run_id: int,
                    findings: list[Finding]) -> dict[str, int]:
    """Insert or update findings, then auto-resolve the ones that disappeared."""
    counts = {"new": 0, "reopened": 0, "still_open": 0, "resolved": 0}
    now = _now(conn)
    seen_keys: set[str] = set()

    for finding in findings:
        seen_keys.add(finding.dedup_key)
        existing = conn.execute(
            "SELECT id, status, first_seen_run_id FROM findings "
            "WHERE project_id = ? AND dedup_key = ?",
            (project_id, finding.dedup_key),
        ).fetchone()

        detail = json.dumps({
            "why": finding.why,
            "remediation": finding.remediation,
            "evidence": finding.evidence,
            "endpoints": finding.endpoints,
            "endpoint_count": finding.endpoint_count,
            "max_score": finding.max_score,
        }, default=str)

        if existing is None:
            conn.execute(
                """INSERT INTO findings
                     (project_id, run_id, rule_id, severity, confidence, title,
                      asset_kind, asset_key, detail_json, dedup_key, status,
                      first_seen_run_id, last_seen_run_id, created_at, updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,'open',?,?,?,?)""",
                (project_id, run_id, finding.rule_id, finding.severity,
                 finding.confidence, finding.title, finding.asset_kind,
                 finding.asset_key, detail, finding.dedup_key,
                 run_id, run_id, now, now),
            )
            counts["new"] += 1
            continue

        # A finding that was resolved and has come back is reopened rather than
        # silently updated, so the history shows the regression.
        reopened = existing["status"] == "resolved"
        conn.execute(
            """UPDATE findings SET
                 run_id = ?, severity = ?, confidence = ?, title = ?,
                 detail_json = ?, last_seen_run_id = ?, updated_at = ?,
                 status = CASE WHEN status = 'resolved' THEN 'open' ELSE status END,
                 resolved_run_id = CASE WHEN status = 'resolved' THEN NULL
                                        ELSE resolved_run_id END
               WHERE id = ?""",
            (run_id, finding.severity, finding.confidence, finding.title,
             detail, run_id, now, existing["id"]),
        )
        counts["reopened" if reopened else "still_open"] += 1

    # Anything previously open that this run did not observe is resolved. The
    # signal is gone, which is the only evidence a scan can offer.
    open_rows = conn.execute(
        "SELECT id, dedup_key FROM findings "
        "WHERE project_id = ? AND status = 'open'",
        (project_id,),
    ).fetchall()
    for row in open_rows:
        if row["dedup_key"] in seen_keys:
            continue
        conn.execute(
            "UPDATE findings SET status = 'resolved', resolved_run_id = ?, "
            "updated_at = ? WHERE id = ?",
            (run_id, now, row["id"]),
        )
        counts["resolved"] += 1

    return counts


def _now(_conn: sqlite3.Connection) -> str:
    from datetime import datetime
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z")


def summarise(findings: list[Finding]) -> dict[str, Any]:
    by_severity: dict[str, int] = {}
    by_rule: dict[str, int] = {}
    for finding in findings:
        by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
        by_rule[finding.rule_id] = by_rule.get(finding.rule_id, 0) + 1

    return {
        "total": len(findings),
        "by_severity": by_severity,
        "by_rule": dict(sorted(by_rule.items(), key=lambda kv: -kv[1])),
        "critical_high": by_severity.get("critical", 0) + by_severity.get("high", 0),
        "affected_hosts": len({f.asset_key for f in findings}),
    }
