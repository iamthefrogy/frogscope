"""Host-grain rollup.

An endpoint-level view answers "which services are exposed"; a host-level view
answers "which machines should someone go fix". `real_port_count` deliberately
excludes Cloudflare alias ports and scan artefacts, because a Cloudflare-fronted
host probed on the full alias set otherwise looks like it runs a dozen services
when it runs one.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from ..config import Config


def build_host_rollups(records: list[dict], cfg: Config) -> list[dict]:
    by_host: dict[str, list[dict]] = defaultdict(list)
    for rec in records:
        by_host[rec["host"]].append(rec)

    rollups: list[dict] = []
    for host, group in sorted(by_host.items()):
        ports = sorted({int(r["port"]) for r in group})
        serving = [r for r in group if r.get("serves_content")]
        real = [
            r for r in group
            if not r.get("scan_artifact") and not r.get("cf_alias_port")
        ]

        ips: list[str] = []
        cnames: list[str] = []
        techs: list[str] = []
        for rec in group:
            for ip in [rec.get("host_ip")] + list(rec.get("a") or []):
                if ip and ip not in ips:
                    ips.append(ip)
            for cn in rec.get("cname") or []:
                if cn not in cnames:
                    cnames.append(cn)
            for tech in rec.get("tech") or []:
                if tech not in techs:
                    techs.append(tech)

        # Distinct (webserver, content signature) pairs — a host answering with
        # three different applications on three ports is worth a closer look.
        diversity = len({
            (r.get("webserver") or "", r.get("content_sig") or "")
            for r in real
        })

        first = group[0]
        unhealthy = [r.get("origin_health") for r in group
                     if r.get("origin_health") not in ("ok", "unknown", None)]

        rollups.append({
            "host": host,
            "host_display": first.get("host_display") or host,
            "env": first.get("env"),
            "zone": first.get("zone"),
            "port_count": len(ports),
            "serving_port_count": len(serving),
            "real_port_count": len({int(r["port"]) for r in real}),
            "ports": ports,
            "ips": ips,
            "distinct_ip_count": len(ips),
            "cnames": cnames,
            "techs": techs,
            "hosting_provider": _majority(group, "hosting_provider"),
            "cdn_name": _majority(group, "cdn_name"),
            "origin_exposed": any(r.get("origin_exposed") for r in group),
            "waf_protected_count": sum(1 for r in group if r.get("waf_protected")),
            "no_waf_count": sum(1 for r in group if r.get("no_waf")),
            "cdn_bypass_candidate": any(r.get("cdn_bypass_candidate") for r in group),
            "has_auth_surface": any(
                r.get("auth_surface_type", "none") != "none" for r in group
            ),
            "has_mgmt_surface": any(r.get("mgmt_surface") for r in group),
            "origin_health": unhealthy[0] if unhealthy else "ok",
            "service_diversity": diversity,
            "owner": first.get("owner"),
            "business_unit": first.get("business_unit"),
            "criticality": first.get("criticality"),
        })
    return rollups


def _majority(group: list[dict], field: str) -> Any:
    counts: dict[Any, int] = defaultdict(int)
    for rec in group:
        value = rec.get(field)
        if value:
            counts[value] += 1
    if not counts:
        return ""
    return max(counts.items(), key=lambda kv: kv[1])[0]
