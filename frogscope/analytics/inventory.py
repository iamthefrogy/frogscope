"""Inventory aggregations: technology, infrastructure, authentication, takeover.

Everything here counts **hosts**, not endpoints. A Cloudflare-fronted host
contributes a dozen near-identical endpoints, so endpoint counts in an inventory
overstate every total several-fold — "1,785 endpoints run Cloudflare" is true and
useless; "343 hosts" is the number somebody can act on.
"""

from __future__ import annotations

import json
import sqlite3
from collections import defaultdict
from typing import Any

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


def _lists(row: sqlite3.Row) -> dict:
    try:
        return json.loads(row["lists_json"] or "{}") or {}
    except (json.JSONDecodeError, TypeError):
        return {}


def _endpoints(conn: sqlite3.Connection, run_id: int, *,
               columns: str = "*") -> list[sqlite3.Row]:
    return conn.execute(
        f"SELECT {columns} FROM endpoints WHERE run_id = ?", (run_id,)
    ).fetchall()


# ── Technology and lifecycle ────────────────────────────────────────────────

def technology(conn: sqlite3.Connection, run_id: int,
               lifecycle: dict | None = None) -> dict[str, Any]:
    """Every detected technology and CPE, counted by host.

    Version spread is worth surfacing on its own: one product at four different
    versions across the estate is a patching-consistency problem that a single
    "outdated" flag hides.
    """
    tech_hosts: dict[str, set[str]] = defaultdict(set)
    tech_versions: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    cpe_hosts: dict[str, set[str]] = defaultdict(set)
    eol_by_product: dict[str, dict[str, Any]] = {}
    outdated: dict[str, dict[str, Any]] = {}
    wp_plugins: dict[str, set[str]] = defaultdict(set)
    server_hosts: dict[str, set[str]] = defaultdict(set)

    for row in _endpoints(conn, run_id,
                          columns="host, lists_json, webserver, is_wordpress"):
        host = row["host"]
        lists = _lists(row)

        for name in lists.get("tech_names") or lists.get("tech") or []:
            tech_hosts[str(name)].add(host)
        for name, version in (lists.get("tech_versions") or {}).items():
            tech_versions[str(name)][str(version)].add(host)
        for product in lists.get("cpe_products") or []:
            cpe_hosts[str(product)].add(host)
        for plugin in lists.get("wp_plugins") or []:
            wp_plugins[str(plugin)].add(host)
        if row["webserver"]:
            server_hosts[row["webserver"]].add(host)

        for entry in lists.get("eol_details") or []:
            key = entry.get("name") or "unknown"
            record = eol_by_product.setdefault(key, {
                "name": key,
                "product": entry.get("product"),
                "eol_date": entry.get("eol_date"),
                "years_past_eol": entry.get("years_past_eol"),
                "severity": entry.get("severity", "high"),
                "note": (entry.get("note") or "").strip(),
                "hosts": set(),
            })
            record["hosts"].add(host)

        for entry in lists.get("outdated_details") or []:
            key = entry.get("name") or "unknown"
            record = outdated.setdefault(key, {
                "name": key, "min_safe": entry.get("min_safe"),
                "versions": set(), "hosts": set(),
            })
            record["versions"].add(str(entry.get("version")))
            record["hosts"].add(host)

    def _spread(name: str) -> dict[str, Any]:
        versions = tech_versions.get(name) or {}
        return {
            "versions": sorted(versions),
            "version_count": len(versions),
            "by_version": {v: len(h) for v, h in sorted(versions.items())},
        }

    tech = [
        {"name": name, "hosts": len(hosts), **_spread(name)}
        for name, hosts in tech_hosts.items()
    ]
    tech.sort(key=lambda t: (-t["hosts"], t["name"]))

    return {
        "tech": tech,
        "inconsistent_versions": [
            t for t in tech if t["version_count"] > 1
        ],
        "cpe": sorted(
            ({"product": p, "hosts": len(h)} for p, h in cpe_hosts.items()),
            key=lambda e: (-e["hosts"], e["product"]),
        ),
        "webservers": sorted(
            ({"name": n, "hosts": len(h)} for n, h in server_hosts.items()),
            key=lambda e: (-e["hosts"], e["name"]),
        ),
        "eol": sorted(
            ({**r, "hosts": len(r["hosts"])} for r in eol_by_product.values()),
            key=lambda e: (-(e["years_past_eol"] or 0), -e["hosts"]),
        ),
        "outdated": sorted(
            ({"name": r["name"], "min_safe": r["min_safe"],
              "versions": sorted(r["versions"]), "hosts": len(r["hosts"])}
             for r in outdated.values()),
            key=lambda e: (-e["hosts"], e["name"]),
        ),
        "wordpress_plugins": sorted(
            ({"name": n, "hosts": len(h)} for n, h in wp_plugins.items()),
            key=lambda e: (-e["hosts"], e["name"]),
        ),
        "totals": {
            "distinct_tech": len(tech_hosts),
            "distinct_cpe": len(cpe_hosts),
            "eol_hosts": len({h for r in eol_by_product.values() for h in r["hosts"]}),
            "wordpress_hosts": len({h for hs in wp_plugins.values() for h in hs}),
        },
    }


# ── Infrastructure ──────────────────────────────────────────────────────────

def infrastructure(conn: sqlite3.Connection, run_id: int,
                   ip_limit: int = 30) -> dict[str, Any]:
    """Addresses, providers, and the port matrix."""
    ip_hosts: dict[str, set[str]] = defaultdict(set)
    ip_meta: dict[str, dict[str, Any]] = {}
    provider_hosts: dict[str, set[str]] = defaultdict(set)
    edge_hosts: dict[str, set[str]] = defaultdict(set)
    chain_hosts: dict[str, set[str]] = defaultdict(set)
    cname_apex: dict[str, set[str]] = defaultdict(set)
    resolver_use: dict[str, set[str]] = defaultdict(set)
    ipv6_hosts: set[str] = set()

    for row in _endpoints(conn, run_id, columns=(
        "host, host_ip, lists_json, hosting_provider, hosting_kind, "
        "edge_provider, cdn_name, ipv6_enabled, third_party_dependency"
    )):
        host = row["host"]
        lists = _lists(row)

        for ip in [row["host_ip"], *(lists.get("a") or []), *(lists.get("aaaa") or [])]:
            if not ip:
                continue
            ip_hosts[str(ip)].add(host)
            meta = ip_meta.setdefault(str(ip), {
                "ip": str(ip), "providers": set(), "cdn": set(),
                "family": "ipv6" if ":" in str(ip) else "ipv4",
            })
            if row["hosting_provider"]:
                meta["providers"].add(row["hosting_provider"])
            if row["cdn_name"]:
                meta["cdn"].add(row["cdn_name"])

        if row["hosting_provider"]:
            provider_hosts[row["hosting_provider"]].add(host)
        if row["edge_provider"]:
            edge_hosts[row["edge_provider"]].add(host)
        for provider in lists.get("chain_providers") or []:
            chain_hosts[str(provider)].add(host)
        for cname in lists.get("cname") or []:
            parts = str(cname).rstrip(".").split(".")
            if len(parts) >= 2:
                cname_apex[".".join(parts[-2:])].add(host)
        for resolver in lists.get("resolvers") or []:
            resolver_use[str(resolver)].add(host)
        if row["ipv6_enabled"]:
            ipv6_hosts.add(host)

    addresses = sorted(
        ({
            "ip": ip,
            "hosts": len(hosts),
            "family": ip_meta[ip]["family"],
            "providers": sorted(ip_meta[ip]["providers"]),
            "cdn": sorted(ip_meta[ip]["cdn"]),
            "sample_hosts": sorted(hosts)[:8],
        } for ip, hosts in ip_hosts.items()),
        key=lambda e: (-e["hosts"], e["ip"]),
    )

    # ── Port matrix ─────────────────────────────────────────────────────────
    # Cell = response class, so the shape of the estate is visible at a glance:
    # which ports are real services, which are Cloudflare aliases, and which are
    # artefacts of probing a TLS-only port over cleartext.
    ports = [
        r["port"] for r in conn.execute(
            "SELECT DISTINCT port FROM endpoints WHERE run_id = ? ORDER BY port",
            (run_id,))
    ]

    port_summary = []
    for row in conn.execute(
        """SELECT port, response_class, COUNT(*) AS n,
                  SUM(scan_artifact) AS artefacts,
                  SUM(CASE WHEN scan_artifact = 0 AND cf_alias_port = 1
                           THEN 1 ELSE 0 END) AS aliases,
                  SUM(serves_content) AS serving,
                  SUM(CASE WHEN cf_alias_port = 0 AND scan_artifact = 0
                           THEN 1 ELSE 0 END) AS real_count
             FROM endpoints WHERE run_id = ?
            GROUP BY port, response_class""", (run_id,)
    ):
        port_summary.append(dict(row))

    by_port: dict[int, dict[str, Any]] = {}
    for entry in port_summary:
        record = by_port.setdefault(entry["port"], {
            "port": entry["port"], "total": 0, "serving": 0,
            "aliases": 0, "artefacts": 0, "real": 0, "by_class": {},
        })
        record["total"] += entry["n"]
        record["serving"] += entry["serving"] or 0
        # The three buckets are mutually exclusive and sum to `total`. An
        # endpoint can be both an alias port and (probed over cleartext) an
        # artefact, so overlapping counts would read as an arithmetic error —
        # artefact wins, since that is the more specific fact.
        record["artefacts"] += entry["artefacts"] or 0
        record["aliases"] += entry["aliases"] or 0
        record["real"] += entry["real_count"] or 0
        record["by_class"][entry["response_class"]] = entry["n"]

    port_rows = sorted(by_port.values(), key=lambda p: p["port"])

    # Host × port grid, ordered by how much genuinely distinct surface each host
    # has. Capped: a full 343-row grid is unreadable and slow to render.
    grid_rows: dict[str, dict[str, Any]] = {}
    for row in conn.execute(
        """SELECT host, host_display, port, response_class, cf_alias_port,
                  scan_artifact, serves_content, risk_band
             FROM endpoints WHERE run_id = ?""", (run_id,)
    ):
        entry = grid_rows.setdefault(row["host"], {
            "host": row["host"], "host_display": row["host_display"],
            "cells": {}, "real_ports": 0, "serving": 0,
        })
        entry["cells"][str(row["port"])] = {
            "response_class": row["response_class"],
            "alias": bool(row["cf_alias_port"]),
            "artefact": bool(row["scan_artifact"]),
            "band": row["risk_band"],
        }
        if not row["cf_alias_port"] and not row["scan_artifact"]:
            entry["real_ports"] += 1
        if row["serves_content"]:
            entry["serving"] += 1

    grid = sorted(grid_rows.values(),
                  key=lambda e: (-e["real_ports"], -e["serving"], e["host"]))

    return {
        "addresses": addresses[:ip_limit],
        "address_total": len(addresses),
        "concentration": [a for a in addresses if a["hosts"] >= 20][:ip_limit],
        "providers": sorted(
            ({"name": n, "hosts": len(h)} for n, h in provider_hosts.items()),
            key=lambda e: (-e["hosts"], e["name"]),
        ),
        "edge_providers": sorted(
            ({"name": n, "hosts": len(h)} for n, h in edge_hosts.items()),
            key=lambda e: (-e["hosts"], e["name"]),
        ),
        "supply_chain": sorted(
            ({"name": n, "hosts": len(h)} for n, h in chain_hosts.items()),
            key=lambda e: (-e["hosts"], e["name"]),
        ),
        "cname_apex": sorted(
            ({"apex": a, "hosts": len(h)} for a, h in cname_apex.items()),
            key=lambda e: (-e["hosts"], e["apex"]),
        )[:30],
        "resolvers": sorted(
            ({"resolver": r, "hosts": len(h)} for r, h in resolver_use.items()),
            key=lambda e: (-e["hosts"], e["resolver"]),
        ),
        "ports": ports,
        "port_rows": port_rows,
        "grid": grid,
        "grid_total": len(grid),
        "ipv6_hosts": len(ipv6_hosts),
    }


# ── Authentication surfaces ─────────────────────────────────────────────────

def auth_surfaces(conn: sqlite3.Connection, run_id: int) -> dict[str, Any]:
    """Every login, admin, and remote-access portal, grouped by type.

    Federated and local authentication are reported separately, because
    federation is a *good* property — the risk is a surface that handles
    credentials itself.
    """
    groups: dict[str, dict[str, Any]] = {}
    remote_access: list[dict] = []
    mgmt: list[dict] = []
    over_http: list[dict] = []

    for row in conn.execute(
        """SELECT host, host_display, endpoint_key, port, scheme,
                  auth_surface_type, federated_auth, final_host, waf_protected,
                  no_waf, remote_access_exposed, mgmt_surface, no_tls_redirect,
                  risk_band, risk_score, title, lists_json, status_code, env
             FROM endpoints
            WHERE run_id = ? AND scan_artifact = 0
              AND (auth_surface_type != 'none' OR remote_access_exposed = 1
                   OR mgmt_surface = 1)""", (run_id,)
    ):
        lists = _lists(row)
        record = {
            "endpoint_key": row["endpoint_key"],
            "host": row["host"],
            "host_display": row["host_display"],
            "port": row["port"],
            "scheme": row["scheme"],
            "type": row["auth_surface_type"],
            "federated": bool(row["federated_auth"]),
            "idp": row["final_host"] or "",
            "waf_protected": bool(row["waf_protected"]),
            "no_waf": bool(row["no_waf"]),
            "over_http": bool(row["no_tls_redirect"]),
            "risk_band": row["risk_band"],
            "risk_score": row["risk_score"],
            "title": row["title"],
            "env": row["env"],
            "cpe": lists.get("cpe_products") or [],
        }

        if row["auth_surface_type"] != "none":
            group = groups.setdefault(row["auth_surface_type"], {
                "type": row["auth_surface_type"], "hosts": set(),
                "endpoints": [], "federated": 0, "local": 0,
                "no_waf": 0, "over_http": 0,
            })
            group["hosts"].add(row["host"])
            group["endpoints"].append(record)
            group["federated" if record["federated"] else "local"] += 1
            if record["no_waf"]:
                group["no_waf"] += 1
            if record["over_http"]:
                group["over_http"] += 1

        if row["remote_access_exposed"]:
            remote_access.append(record)
        if row["mgmt_surface"]:
            mgmt.append(record)
        if record["over_http"]:
            over_http.append(record)

    out_groups = []
    for group in groups.values():
        endpoints = sorted(group["endpoints"],
                           key=lambda e: (-(e["risk_score"] or 0), e["endpoint_key"]))
        out_groups.append({
            **group,
            "hosts": len(group["hosts"]),
            "endpoints": endpoints[:200],
            "endpoint_count": len(group["endpoints"]),
        })
    out_groups.sort(key=lambda g: -g["hosts"])

    def _dedupe_by_host(records: list[dict]) -> list[dict]:
        seen: dict[str, dict] = {}
        for record in sorted(records,
                             key=lambda e: -(e["risk_score"] or 0)):
            seen.setdefault(record["host"], record)
        return list(seen.values())

    return {
        "groups": out_groups,
        "remote_access": _dedupe_by_host(remote_access),
        "management": _dedupe_by_host(mgmt),
        "over_http": _dedupe_by_host(over_http),
        "totals": {
            "hosts": len({e["host"] for g in groups.values()
                          for e in g["endpoints"]}),
            "federated": sum(g["federated"] for g in groups.values()),
            "local": sum(g["local"] for g in groups.values()),
            "remote_access_hosts": len({r["host"] for r in remote_access}),
            "management_hosts": len({r["host"] for r in mgmt}),
        },
    }


# ── Takeover candidates ─────────────────────────────────────────────────────

def takeover(conn: sqlite3.Connection, run_id: int,
             takeover_cfg: dict | None = None) -> dict[str, Any]:
    """Graded candidates, with the evidence and a way to check them.

    Never asserted as confirmed. Ingest makes no network requests, so the
    strongest grade reachable from scan data alone is "likely dangling" — turning
    that into a confirmed finding needs a live DNS and provider check.
    """
    takeover_cfg = takeover_cfg or {}
    grades = takeover_cfg.get("grades") or {}

    by_host: dict[str, dict[str, Any]] = {}
    for row in conn.execute(
        """SELECT host, host_display, endpoint_key, port, status_code,
                  takeover_grade, takeover_provider, takeover_confidence,
                  origin_health, cf_error_code, cname_final, title,
                  lists_json, risk_score, risk_band, env, zone
             FROM endpoints
            WHERE run_id = ? AND takeover_grade != ''""", (run_id,)
    ):
        lists = _lists(row)
        entry = by_host.setdefault(row["host"], {
            "host": row["host"],
            "host_display": row["host_display"],
            "grade": row["takeover_grade"],
            "provider": row["takeover_provider"],
            "confidence": row["takeover_confidence"],
            "origin_health": row["origin_health"],
            "cf_error_code": row["cf_error_code"],
            "cname": lists.get("cname") or [],
            "cname_final": row["cname_final"],
            "title": row["title"],
            "status_code": row["status_code"],
            "env": row["env"],
            "zone": row["zone"],
            "endpoints": [],
            "evidence": lists.get("takeover_evidence") or [],
            "risk_score": row["risk_score"],
        })
        entry["endpoints"].append(row["endpoint_key"])
        ranking = {"high": 3, "medium": 2, "low": 1, "": 0}
        if ranking.get(row["takeover_grade"], 0) > ranking.get(entry["grade"], 0):
            entry.update({
                "grade": row["takeover_grade"],
                "provider": row["takeover_provider"],
                "confidence": row["takeover_confidence"],
                "evidence": lists.get("takeover_evidence") or entry["evidence"],
            })

    candidates = sorted(
        by_host.values(),
        key=lambda e: ({"high": 0, "medium": 1, "low": 2}.get(e["grade"], 3),
                       -(e["risk_score"] or 0), e["host"]),
    )

    for candidate in candidates:
        target = candidate["cname_final"] or candidate["host"]
        candidate["verify_commands"] = [
            f"dig +short {candidate['host']} CNAME",
            f"dig +short {target}",
            f"curl -sSI --max-time 10 https://{candidate['host']}/",
        ]
        candidate["grade_label"] = (
            grades.get(candidate["grade"], {}).get("label") or candidate["grade"])
        candidate["grade_description"] = (
            grades.get(candidate["grade"], {}).get("description") or "")

    # Broken origins are deliberately kept apart. A 525 means the origin answers
    # but its TLS is broken — an availability bug, not a dangling record. Merging
    # the two is how a takeover feed loses credibility.
    broken = [
        dict(r) for r in conn.execute(
            """SELECT DISTINCT host, host_display, origin_health, cf_error_code,
                      status_code, title
                 FROM endpoints
                WHERE run_id = ? AND origin_health NOT IN ('ok', 'unknown', '')
                  AND takeover_grade = ''""", (run_id,))
    ]

    return {
        "candidates": candidates,
        "broken_origins": broken,
        "by_grade": {
            grade: sum(1 for c in candidates if c["grade"] == grade)
            for grade in ("high", "medium", "low")
            if any(c["grade"] == grade for c in candidates)
        },
        "verify_note": (takeover_cfg.get("verify_note") or "").strip(),
        "totals": {
            "candidate_hosts": len(candidates),
            "broken_origin_hosts": len(broken),
        },
    }
