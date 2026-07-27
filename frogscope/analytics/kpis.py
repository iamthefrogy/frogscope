"""Executive KPI computation.

The unit of remediation is a **host**, not an endpoint. Somebody fixes
"adm.iem.example.com", not "adm.iem.example.com:2082". Endpoint-weighted
averages therefore mislead badly here: a Cloudflare-fronted host contributes a
dozen near-identical endpoints, so a healthy majority of endpoints can coexist
with most of the estate needing attention.

On the real data that gap is stark — 91/100 endpoint-weighted against 63% of
hosts carrying a critical or high finding. So the headline is a host count, and
the index is reported beside it with its basis stated rather than presented as
a single verdict.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
SEVERITY_WEIGHT = {"critical": 1.0, "high": 0.6, "medium": 0.3, "low": 0.1,
                   "info": 0.0}


def _rows(conn: sqlite3.Connection, sql: str, params: tuple = ()) -> list[dict]:
    return [dict(r) for r in conn.execute(sql, params)]


def _one(conn: sqlite3.Connection, sql: str, params: tuple = ()) -> Any:
    row = conn.execute(sql, params).fetchone()
    return row[0] if row else None


# ── Host posture ────────────────────────────────────────────────────────────

def host_posture(conn: sqlite3.Connection, run_id: int,
                 project_id: int) -> dict[str, Any]:
    """Hosts bucketed by their worst open finding.

    This is the number that drives remediation planning, and it is deliberately
    based on finding severity rather than the score band: a critical issue on an
    otherwise quiet host still needs someone to act.
    """
    total = _one(conn, "SELECT COUNT(*) FROM host_rollup WHERE run_id = ?",
                 (run_id,)) or 0

    worst: dict[str, str] = {}
    for row in conn.execute(
        "SELECT asset_key, severity FROM findings "
        "WHERE project_id = ? AND status != 'resolved'", (project_id,)
    ):
        current = worst.get(row["asset_key"])
        if current is None or (SEVERITY_ORDER.index(row["severity"])
                               < SEVERITY_ORDER.index(current)):
            worst[row["asset_key"]] = row["severity"]

    buckets = dict.fromkeys(SEVERITY_ORDER, 0)
    for severity in worst.values():
        buckets[severity] = buckets.get(severity, 0) + 1
    clean = max(0, total - len(worst))

    needs_attention = buckets["critical"] + buckets["high"]
    weighted = sum(SEVERITY_WEIGHT[s] * n for s, n in buckets.items())
    # One decimal: when the estate grows proportionally the index drifts by
    # fractions of a point, and an integer would report that as no change.
    index = round(100 * (1 - min(1.0, weighted / total)), 1) if total else 100.0

    return {
        "total_hosts": total,
        "by_worst_finding": {k: v for k, v in buckets.items() if v},
        "clean": clean,
        "needs_attention": needs_attention,
        "needs_attention_pct": round(100 * needs_attention / total, 1) if total else 0.0,
        "index": index,
        "index_basis": "host",
        "formula": (
            "100 x (1 - sum(severity weight of each host's worst open finding) / "
            "total hosts), weights critical 1.0, high 0.6, medium 0.3, low 0.1. "
            "Host-weighted because a host is the unit of remediation."
        ),
    }


# ── Protection composition ──────────────────────────────────────────────────

def protection(conn: sqlite3.Connection, run_id: int) -> dict[str, Any]:
    """How much of the real surface has something in front of it.

    Cloudflare alias ports and scan artefacts are excluded: an alias port serves
    the same origin site as :443, so counting it again would overstate coverage
    for whichever category it lands in.
    """
    rows = _rows(conn, """
        SELECT CASE
                 WHEN waf_protected = 1 THEN 'waf'
                 WHEN behind_proxy = 1  THEN 'platform'
                 WHEN serves_content = 1 THEN 'none'
                 ELSE 'not_serving'
               END AS layer,
               COUNT(*) AS n
        FROM endpoints
        WHERE run_id = ? AND scan_artifact = 0 AND cf_alias_port = 0
        GROUP BY 1
    """, (run_id,))
    counts = {r["layer"]: r["n"] for r in rows}

    segments = [
        {"key": "waf", "label": "WAF or CDN inspecting traffic",
         "count": counts.get("waf", 0), "good": True},
        {"key": "platform", "label": "Managed platform, but no WAF",
         "count": counts.get("platform", 0), "good": None},
        {"key": "none", "label": "Nothing in front",
         "count": counts.get("none", 0), "good": False},
        {"key": "not_serving", "label": "Not serving content",
         "count": counts.get("not_serving", 0), "good": None},
    ]
    total = sum(s["count"] for s in segments) or 1
    for segment in segments:
        segment["pct"] = round(100 * segment["count"] / total, 1)

    return {"segments": segments, "total": total,
            "unprotected": counts.get("none", 0)}


# ── Distribution cuts ───────────────────────────────────────────────────────

def by_dimension(conn: sqlite3.Connection, run_id: int, project_id: int,
                 dimension: str = "zone", limit: int = 12) -> list[dict]:
    """Hosts and their worst finding, grouped by zone or environment.

    Answers "where should effort go" without needing an ownership register.
    """
    if dimension not in ("zone", "env", "hosting_provider"):
        raise ValueError(f"unsupported dimension {dimension!r}")

    hosts = _rows(conn, f"""
        SELECT host, {dimension} AS dim, risk_score
        FROM host_rollup WHERE run_id = ?
    """, (run_id,))

    worst: dict[str, str] = {}
    for row in conn.execute(
        "SELECT asset_key, severity FROM findings "
        "WHERE project_id = ? AND status != 'resolved'", (project_id,)
    ):
        current = worst.get(row["asset_key"])
        if current is None or (SEVERITY_ORDER.index(row["severity"])
                               < SEVERITY_ORDER.index(current)):
            worst[row["asset_key"]] = row["severity"]

    grouped: dict[str, dict[str, Any]] = {}
    for host in hosts:
        key = host["dim"] or "unclassified"
        entry = grouped.setdefault(key, {
            "dimension": key, "hosts": 0, "needs_attention": 0,
            "by_severity": {}, "max_score": 0,
        })
        entry["hosts"] += 1
        entry["max_score"] = max(entry["max_score"], host["risk_score"] or 0)
        severity = worst.get(host["host"])
        if severity:
            entry["by_severity"][severity] = entry["by_severity"].get(severity, 0) + 1
            if severity in ("critical", "high"):
                entry["needs_attention"] += 1

    out = sorted(grouped.values(),
                 key=lambda e: (-e["needs_attention"], -e["hosts"]))
    return out[:limit]


# ── Themes ──────────────────────────────────────────────────────────────────

def themes(conn: sqlite3.Connection, project_id: int, ruleset,
           limit: int = 8) -> list[dict]:
    """The most widespread serious problems, as themes rather than rows.

    An executive wants "47 hosts run software the vendor stopped patching", not
    47 individual findings.
    """
    rows = _rows(conn, """
        SELECT rule_id, severity, confidence,
               COUNT(DISTINCT asset_key) AS hosts,
               MAX(title) AS title
        FROM findings
        WHERE project_id = ? AND status != 'resolved'
          AND severity IN ('critical', 'high', 'medium')
        GROUP BY rule_id, severity, confidence
    """, (project_id,))

    rule_index = {r.id: r for r in ruleset.rules}
    out: list[dict] = []
    for row in rows:
        rule = rule_index.get(row["rule_id"])
        out.append({
            "rule_id": row["rule_id"],
            "severity": row["severity"],
            "confidence": row["confidence"],
            "title": row["title"],
            "hosts": row["hosts"],
            "exec_line": (rule.exec_line if rule else "") or row["title"],
            "remediation": rule.remediation if rule else "",
            "bucket": rule.bucket if rule else "",
        })

    out.sort(key=lambda t: (SEVERITY_ORDER.index(t["severity"]), -t["hosts"]))
    return out[:limit]


def top_hosts(conn: sqlite3.Connection, run_id: int, project_id: int,
              limit: int = 10) -> list[dict]:
    """Highest-risk hosts, each with its worst finding named in plain English."""
    hosts = _rows(conn, """
        SELECT host, host_display, risk_score, risk_band, finding_count,
               env, zone, hosting_provider, origin_exposed, cdn_bypass_candidate
        FROM host_rollup WHERE run_id = ? ORDER BY risk_score DESC LIMIT ?
    """, (run_id, limit))

    for host in hosts:
        rows = _rows(conn, """
            SELECT severity, title, rule_id FROM findings
            WHERE project_id = ? AND asset_key = ? AND status != 'resolved'
        """, (project_id, host["host"]))
        rows.sort(key=lambda r: SEVERITY_ORDER.index(r["severity"]))
        host["worst_finding"] = rows[0] if rows else None
        host["worst_severity"] = rows[0]["severity"] if rows else None
        host["other_findings"] = [r["title"] for r in rows[1:4]]
    return hosts


# ── Surface facts ───────────────────────────────────────────────────────────

def surface(conn: sqlite3.Connection, run_id: int, run: sqlite3.Row) -> dict[str, Any]:
    try:
        stored = json.loads(run["summary_json"] or "{}")
    except (json.JSONDecodeError, TypeError):
        stored = {}

    return {
        "hosts": stored.get("hosts", 0),
        "endpoints": stored.get("endpoints", 0),
        "real_endpoints": stored.get("real_endpoints", 0),
        "scan_artifacts": stored.get("scan_artifacts", 0),
        "cf_alias_ports": stored.get("cf_alias_ports", 0),
        "serving": stored.get("serving", 0),
        "no_waf": stored.get("no_waf", 0),
        "no_waf_hosts": stored.get("no_waf_hosts", 0),
        "origin_exposed_hosts": stored.get("origin_exposed_hosts", 0),
        "cdn_bypass_hosts": stored.get("cdn_bypass_hosts", 0),
        "auth_surfaces": stored.get("auth_surfaces", 0),
        "mgmt_surfaces": stored.get("mgmt_surfaces", 0),
        "remote_access": stored.get("remote_access", 0),
        "azure_app_proxy": stored.get("azure_app_proxy", 0),
        "nonprod_exposed": stored.get("nonprod_exposed", 0),
        "broken_origin": stored.get("broken_origin", 0),
        "unique_ips": stored.get("unique_ips", 0),
        "ports": stored.get("ports", []),
    }


def eol_summary(conn: sqlite3.Connection, run_id: int) -> dict[str, Any]:
    products: dict[str, dict[str, Any]] = {}
    for row in conn.execute("""
        SELECT lists_json, host, eol_years_past FROM endpoints
        WHERE run_id = ? AND eol_count > 0
    """, (run_id,)):
        try:
            details = (json.loads(row["lists_json"] or "{}") or {}).get("eol_details")
        except json.JSONDecodeError:
            continue
        for entry in details or []:
            key = entry.get("name") or "unknown"
            record = products.setdefault(key, {
                "name": key, "eol_date": entry.get("eol_date"),
                "severity": entry.get("severity"), "hosts": set(),
                "years_past_eol": entry.get("years_past_eol"),
                "note": entry.get("note", ""),
            })
            record["hosts"].add(row["host"])

    out = [
        {**record, "hosts": len(record["hosts"])}
        for record in products.values()
    ]
    out.sort(key=lambda p: (-(p["years_past_eol"] or 0), -p["hosts"]))
    return {"products": out,
            "host_count": _one(conn, "SELECT COUNT(DISTINCT host) FROM endpoints "
                                     "WHERE run_id = ? AND eol_count > 0",
                               (run_id,)) or 0}


def coverage_caveats(conn: sqlite3.Connection, run_id: int,
                     run: sqlite3.Row) -> list[str]:
    """What this scan could not see.

    Stated on the executive page on purpose: a clean number derived from thin
    data is worse than an obviously incomplete one, because it invites
    confidence nobody has earned.
    """
    caveats: list[str] = []

    try:
        risk = json.loads(run["risk_summary_json"] or "{}")
    except (json.JSONDecodeError, TypeError):
        risk = {}

    skipped = risk.get("skipped_rules") or []
    if skipped:
        names = ", ".join(s["rule_id"] for s in skipped[:4])
        caveats.append(
            f"{len(skipped)} scoring rule(s) could not be evaluated because this "
            f"scan did not collect the data they need ({names}). They are "
            f"skipped, not treated as passing."
        )

    empty = _one(conn, "SELECT COUNT(*) FROM run_columns "
                       "WHERE run_id = ? AND fill_pct = 0", (run_id,)) or 0
    total_columns = _one(conn, "SELECT COUNT(*) FROM run_columns WHERE run_id = ?",
                         (run_id,)) or 0
    if empty:
        caveats.append(
            f"{empty} of {total_columns} httpx fields were empty in this scan, so "
            f"certificate, TLS, and screenshot analysis is unavailable."
        )

    if run["incomplete"]:
        caveats.append(
            "This run was flagged as possibly incomplete when it was ingested, so "
            "the totals may understate the real surface."
        )

    artefacts = _one(conn, "SELECT COUNT(*) FROM endpoints "
                           "WHERE run_id = ? AND scan_artifact = 1", (run_id,)) or 0
    if artefacts:
        caveats.append(
            f"{artefacts} probe results were scan artefacts (a TLS-only port "
            f"probed over cleartext) and are excluded from every figure here."
        )

    caveats.append(
        "Everything here comes from an unauthenticated HTTP probe. It shows what "
        "is reachable and probably running; it does not prove anything is "
        "exploitable."
    )
    return caveats


# ── Assembly ────────────────────────────────────────────────────────────────

def build(conn: sqlite3.Connection, run: sqlite3.Row, ruleset) -> dict[str, Any]:
    run_id, project_id = run["id"], run["project_id"]

    try:
        risk = json.loads(run["risk_summary_json"] or "{}")
    except (json.JSONDecodeError, TypeError):
        risk = {}

    posture = host_posture(conn, run_id, project_id)
    findings_by_severity = risk.get("by_severity", {})

    return {
        "run": {
            "id": run_id,
            "run_key": run["run_key"],
            "label": run["label"],
            "started_at": run["started_at"],
            "completed_at": run["completed_at"],
            "scan_duration_s": run["scan_duration_s"],
            "incomplete": bool(run["incomplete"]),
            # sqlite3.Row has no .get(), so this cannot be simplified.
        "rules_hash": (run["rules_hash"]
                       if "rules_hash" in run.keys() else None),
            "is_baseline": bool(run["is_baseline"]),
        },
        "posture": posture,
        "surface": surface(conn, run_id, run),
        "protection": protection(conn, run_id),
        "findings": {
            "total": risk.get("total", 0),
            "by_severity": {
                k: findings_by_severity[k] for k in SEVERITY_ORDER
                if k in findings_by_severity
            },
            "affected_hosts": risk.get("affected_hosts", 0),
        },
        "endpoint_index": risk.get("residual_risk", {}),
        "themes": themes(conn, project_id, ruleset),
        "top_hosts": top_hosts(conn, run_id, project_id),
        "by_zone": by_dimension(conn, run_id, project_id, "zone"),
        "by_env": by_dimension(conn, run_id, project_id, "env"),
        "eol": eol_summary(conn, run_id),
        "caveats": coverage_caveats(conn, run_id, run),
        # Trends need a second run. Reported explicitly rather than drawn as an
        # empty chart, which reads as "no change" instead of "no data".
        "comparison": {
            "available": False,
            "reason": "Only one scan has been ingested. Deltas and trend lines "
                      "need at least two.",
        },
    }
