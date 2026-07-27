"""Materialise per-run metrics for the trend charts.

Long format — one row per (run, metric, dimension, value) — so a trend chart is a
single indexed query rather than a re-scan of every stored run, and adding a
metric needs no schema change.

Rebuilt from scratch for a run each time, so a re-ingest or a rescore leaves no
stale rows behind.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any

# Cuts worth having per run. Each becomes (metric, dim, dim_value, value).
DIMENSIONS = ("env", "zone", "risk_band", "response_class", "hosting_provider",
              "port_category")


def _put(rows: list[tuple], run_id: int, metric: str, value: Any,
         dim: str = "all", dim_value: str = "all") -> None:
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        return
    rows.append((run_id, metric, dim, dim_value, numeric))


def materialise(conn: sqlite3.Connection, run_id: int,
                run: sqlite3.Row) -> int:
    """Write every metric for one run. Returns the row count."""
    rows: list[tuple] = []

    try:
        summary = json.loads(run["summary_json"] or "{}")
    except (json.JSONDecodeError, TypeError):
        summary = {}
    try:
        risk = json.loads(run["risk_summary_json"] or "{}")
    except (json.JSONDecodeError, TypeError):
        risk = {}

    # ── Headline scalars, straight from the stored summaries ────────────────
    for key in ("hosts", "endpoints", "real_endpoints", "serving", "no_waf",
                "no_waf_hosts", "origin_exposed_hosts", "cdn_bypass_hosts",
                "auth_surfaces", "mgmt_surfaces", "remote_access",
                "nonprod_exposed", "broken_origin", "unique_ips",
                "scan_artifacts", "cf_alias_ports", "azure_app_proxy",
                "cleartext_no_upgrade"):
        _put(rows, run_id, key, summary.get(key, 0))

    _put(rows, run_id, "findings_total", risk.get("total", 0))
    for severity, count in (risk.get("by_severity") or {}).items():
        _put(rows, run_id, f"findings_{severity}", count)
        _put(rows, run_id, "findings", count, "severity", severity)


    residual = risk.get("residual_risk") or {}
    _put(rows, run_id, "posture_index_endpoint", residual.get("index"))

    # ── Recomputed from the endpoint rows ──────────────────────────────────
    _put(rows, run_id, "eol_hosts", conn.execute(
        "SELECT COUNT(DISTINCT host) n FROM endpoints "
        "WHERE run_id = ? AND eol_count > 0", (run_id,)).fetchone()["n"])
    _put(rows, run_id, "takeover_candidates", conn.execute(
        "SELECT COUNT(*) n FROM endpoints WHERE run_id = ? "
        "AND takeover_grade IN ('high','medium')", (run_id,)).fetchone()["n"])

    # Host posture: the number the executive page leads with, so it has to be in
    # the timeseries too or the trend would disagree with the headline.
    #
    # Derived from `asset_scores` for THIS run, not from the `findings` table.
    # findings.last_seen_run_id is a moving pointer: once a finding is re-observed
    # in a later run it stops identifying the earlier one, so a metric built on it
    # silently rewrites its own history. asset_scores is written once per
    # (run, endpoint) and never mutated, which is what makes these points stable
    # and `reindex` safe.
    order = ("critical", "high", "medium", "low", "info")
    worst: dict[str, str] = {}
    per_severity: dict[str, set[str]] = {}
    for row in conn.execute(
        """SELECT s.endpoint_key, s.excluded, s.contributions_json, e.host
             FROM asset_scores s
             JOIN endpoints e ON e.run_id = s.run_id
                            AND e.endpoint_key = s.endpoint_key
            WHERE s.run_id = ?""", (run_id,)
    ):
        if row["excluded"]:
            continue
        try:
            contributions = json.loads(row["contributions_json"] or "[]")
        except json.JSONDecodeError:
            continue
        for entry in contributions:
            if entry.get("family") == "positive" or entry.get("severity") == "info":
                continue
            severity = entry.get("severity")
            # Findings are per (rule, host), matching how the Findings view
            # deduplicates them.
            per_severity.setdefault(severity, set()).add(
                f"{entry.get('rule_id')}:{row['host']}")
            current = worst.get(row["host"])
            if current is None or order.index(severity) < order.index(current):
                worst[row["host"]] = severity

    for severity, keys in per_severity.items():
        _put(rows, run_id, f"findings_{severity}_in_run", len(keys))
    _put(rows, run_id, "findings_open_in_run",
         sum(len(v) for v in per_severity.values()))

    total_hosts = conn.execute(
        "SELECT COUNT(*) n FROM host_rollup WHERE run_id = ?",
        (run_id,)).fetchone()["n"]
    needs = sum(1 for s in worst.values() if s in ("critical", "high"))
    _put(rows, run_id, "hosts_needing_attention", needs)
    _put(rows, run_id, "hosts_clean", max(0, total_hosts - len(worst)))

    weights = {"critical": 1.0, "high": 0.6, "medium": 0.3, "low": 0.1, "info": 0.0}
    weighted = sum(weights.get(s, 0.0) for s in worst.values())
    _put(rows, run_id, "posture_index_host",
         round(100 * (1 - min(1.0, weighted / total_hosts)), 1)
         if total_hosts else 100.0)

    # ── Dimensional cuts ───────────────────────────────────────────────────
    for dim in DIMENSIONS:
        for row in conn.execute(
            f'SELECT "{dim}" AS v, COUNT(*) AS n FROM endpoints '
            f"WHERE run_id = ? AND scan_artifact = 0 GROUP BY 1", (run_id,)
        ):
            _put(rows, run_id, "endpoints", row["n"], dim, str(row["v"] or "unknown"))

    for row in conn.execute(
        "SELECT env AS v, COUNT(*) AS n FROM host_rollup WHERE run_id = ? "
        "GROUP BY 1", (run_id,)
    ):
        _put(rows, run_id, "hosts", row["n"], "env", str(row["v"] or "unknown"))

    for row in conn.execute(
        "SELECT rule_id, COUNT(DISTINCT asset_key) AS n FROM findings "
        "WHERE last_seen_run_id = ? GROUP BY 1", (run_id,)
    ):
        _put(rows, run_id, "finding_hosts", row["n"], "rule", row["rule_id"])

    # ── Change counts, so churn is itself a trend ──────────────────────────
    try:
        diff = json.loads(run["diff_json"] or "{}")
    except (json.JSONDecodeError, TypeError):
        diff = {}
    for key in ("added", "removed", "modified", "returned", "worse", "better"):
        if key in diff:
            _put(rows, run_id, f"changes_{key}", diff[key])

    conn.execute("DELETE FROM run_metrics WHERE run_id = ?", (run_id,))
    conn.executemany(
        "INSERT OR REPLACE INTO run_metrics "
        "(run_id, metric, dim, dim_value, value) VALUES (?,?,?,?,?)",
        rows,
    )
    return len(rows)


def series(conn: sqlite3.Connection, project_id: int, metric: str,
           dim: str = "all", limit: int = 24) -> list[dict[str, Any]]:
    """One metric across runs, oldest first — the shape a trend chart wants."""
    rows = conn.execute(
        """SELECT r.id AS run_id, r.run_key, r.label, r.started_at,
                  r.incomplete, r.rules_hash, m.dim_value, m.value
             FROM run_metrics m
             JOIN runs r ON r.id = m.run_id
            WHERE r.project_id = ? AND m.metric = ? AND m.dim = ?
              AND r.duplicate_of IS NULL
            ORDER BY COALESCE(r.started_at,''), r.id""",
        (project_id, metric, dim),
    ).fetchall()

    out = [dict(r) for r in rows]
    return out[-limit:] if limit else out


def available_metrics(conn: sqlite3.Connection,
                      project_id: int) -> list[dict[str, Any]]:
    rows = conn.execute(
        """SELECT m.metric, m.dim, COUNT(DISTINCT m.run_id) AS runs
             FROM run_metrics m JOIN runs r ON r.id = m.run_id
            WHERE r.project_id = ? AND r.duplicate_of IS NULL
            GROUP BY m.metric, m.dim ORDER BY m.metric, m.dim""",
        (project_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def rebuild_all(conn: sqlite3.Connection, project_id: int | None = None) -> int:
    """Recompute metrics for every run.

    Needed after a backfill reorders the timeline, or after a rescore changes the
    numbers the metrics are derived from.
    """
    sql = "SELECT * FROM runs WHERE duplicate_of IS NULL"
    params: tuple = ()
    if project_id is not None:
        sql += " AND project_id = ?"
        params = (project_id,)
    sql += " ORDER BY COALESCE(started_at,''), id"

    total = 0
    for run in conn.execute(sql, params).fetchall():
        total += materialise(conn, run["id"], run)
    conn.commit()
    return total
