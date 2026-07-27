"""End-of-life, outdated-component, and takeover-candidate derivation.

These fields exist only for scoring, so they live beside the engine rather than
in the general enrichment pass. All of them are claims about a *product* or a
*DNS delegation* inferred from banner data, never confirmed facts — so each one
carries its confidence with it.
"""

from __future__ import annotations

import re
from datetime import date, datetime
from typing import Any

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


def _worst(severities: list[str]) -> str:
    for level in SEVERITY_ORDER:
        if level in severities:
            return level
    return ""


def _parse_version(text: str) -> tuple:
    """Loose version tuple. '10.0.1-beta' -> (10, 0, 1)."""
    parts = re.findall(r"\d+", str(text or ""))
    return tuple(int(p) for p in parts[:4]) or (0,)


def version_lt(left: str, right: str) -> bool:
    a, b = _parse_version(left), _parse_version(right)
    length = max(len(a), len(b))
    a = a + (0,) * (length - len(a))
    b = b + (0,) * (length - len(b))
    return a < b


def _years_since(date_text: str | None, today: date | None = None) -> float | None:
    if not date_text:
        return None
    try:
        when = datetime.strptime(str(date_text), "%Y-%m-%d").date()
    except ValueError:
        return None
    reference = today or date.today()
    return max(0.0, round((reference - when).days / 365.25, 1))


def derive_lifecycle(record: dict, lifecycle: dict, today: date | None = None) -> None:
    """Populate eol_*, outdated_*, and vuln_* fields on a record."""
    products = {str(p).lower() for p in record.get("cpe_products") or []}
    webserver = record.get("webserver") or ""
    tech_flat = " ".join(str(t) for t in record.get("tech") or [])

    # ── End of life ─────────────────────────────────────────────────────────
    eol_hits: list[dict[str, Any]] = []
    for entry in lifecycle.get("eol") or []:
        matched = False
        product = entry.get("product")
        if product and str(product).lower() in products:
            matched = True
        pattern = entry.get("match_regex")
        if not matched and pattern:
            haystack = f"{webserver} {tech_flat}"
            try:
                matched = bool(re.search(pattern, haystack, re.I))
            except re.error:
                matched = False
        if not matched:
            continue

        years = _years_since(entry.get("eol_date"), today)
        eol_hits.append({
            "name": entry.get("name") or product or pattern,
            "product": product,
            "eol_date": entry.get("eol_date"),
            "years_past_eol": years,
            "severity": entry.get("severity", "high"),
            "note": (entry.get("note") or "").strip(),
        })

    record["eol_products"] = [h["name"] for h in eol_hits]
    record["eol_details"] = eol_hits
    record["eol_count"] = len(eol_hits)
    record["eol_worst_severity"] = _worst([h["severity"] for h in eol_hits])
    years_list = [h["years_past_eol"] for h in eol_hits if h["years_past_eol"]]
    record["eol_years_past"] = max(years_list) if years_list else 0.0
    record["eol_summary"] = "; ".join(
        f"{h['name']}"
        + (f" (unsupported since {h['eol_date']})" if h["eol_date"] else "")
        for h in eol_hits
    )

    # ── Outdated components ─────────────────────────────────────────────────
    minimums = {k.lower(): v for k, v in (lifecycle.get("min_versions") or {}).items()}
    outdated: list[dict[str, Any]] = []
    for name, version in (record.get("tech_versions") or {}).items():
        floor = minimums.get(str(name).lower())
        if floor and version_lt(version, floor):
            outdated.append({"name": name, "version": version, "min_safe": floor})

    record["outdated_components"] = [o["name"] for o in outdated]
    record["outdated_details"] = outdated
    record["outdated_count"] = len(outdated)
    record["outdated_summary"] = "; ".join(
        f"{o['name']} {o['version']} (needs {o['min_safe']})" for o in outdated
    )

    # ── Known-vulnerable families ───────────────────────────────────────────
    families: list[dict[str, Any]] = []
    for entry in lifecycle.get("cve_families") or []:
        product = str(entry.get("product") or "").lower()
        if product and product in products:
            families.append({
                "family": entry.get("family") or product,
                "product": entry.get("product"),
                "severity": entry.get("severity", "medium"),
                "note": (entry.get("note") or "").strip(),
            })

    record["vuln_families"] = [f["family"] for f in families]
    record["vuln_details"] = families
    record["vuln_family_count"] = len(families)
    record["vuln_worst_severity"] = _worst([f["severity"] for f in families])
    record["vuln_summary"] = "; ".join(f["family"] for f in families)


def derive_takeover(record: dict, takeover: dict) -> None:
    """Grade a possible dangling DNS record.

    Never asserts a takeover. The strongest grade this can reach from scan data
    alone is "likely dangling", because confirming it needs a live DNS and
    provider check — which ingest deliberately does not perform.
    """
    record.setdefault("takeover_grade", "")
    record.setdefault("takeover_provider", "")
    record.setdefault("takeover_confidence", "")
    record.setdefault("takeover_evidence", [])
    record.setdefault("takeover_verify", "")

    cnames = [str(c).lower() for c in record.get("cname") or []]
    title = str(record.get("title") or "")
    status = record.get("status_code")
    evidence: list[dict[str, str]] = []

    # A Cloudflare 530 means error 1016: the origin DNS record does not resolve.
    # That is the one signal available here that is genuinely about a *missing*
    # target rather than a broken one.
    dangling_health = set(takeover.get("dangling_origin_health") or ["dns_missing"])
    if record.get("origin_health") in dangling_health:
        evidence.append({
            "test": "edge origin resolution",
            "observed": f"status {status} — origin DNS record does not resolve",
            "verdict": "dangling",
        })
        record["takeover_grade"] = "high"
        record["takeover_provider"] = record.get("edge_provider") or "the edge provider"

    for entry in takeover.get("providers") or []:
        suffixes = [str(s).lower() for s in entry.get("cname_suffixes") or []]
        hit = next(
            (c for c in cnames
             if any(c == s or c.endswith("." + s) for s in suffixes)),
            None,
        )
        if not hit:
            continue

        evidence.append({
            "test": "CNAME delegation",
            "observed": f"{hit} delegates to {entry['provider']}",
            "verdict": "claimable provider" if entry.get("claimable")
                       else "third-party provider",
        })

        title_hit = any(
            str(f).lower() in title.lower()
            for f in entry.get("title_fingerprints") or []
        )
        status_hit = status in (entry.get("status_hints") or [])

        if title_hit:
            evidence.append({
                "test": "provider fingerprint",
                "observed": f"page title matches {entry['provider']}'s "
                            f"'resource does not exist' page",
                "verdict": "dangling",
            })
            grade = entry.get("grade", "high")
        elif status_hit and entry.get("claimable"):
            evidence.append({
                "test": "status code",
                "observed": f"status {status} from a provider where unclaimed "
                            f"names can be registered",
                "verdict": "possibly dangling",
            })
            grade = entry.get("grade", "medium")
        else:
            continue

        current = record.get("takeover_grade") or ""
        ranking = {"high": 3, "medium": 2, "low": 1, "": 0}
        if ranking.get(grade, 0) > ranking.get(current, 0):
            record["takeover_grade"] = grade
            record["takeover_provider"] = entry["provider"]
            record["takeover_verify"] = (entry.get("verify") or "").replace(
                "{host}", record.get("host", "")).replace("{cname}", hit)

    if record["takeover_grade"]:
        grades = takeover.get("grades") or {}
        record["takeover_confidence"] = (
            grades.get(record["takeover_grade"], {}).get("confidence", "possible")
        )
        record["takeover_evidence"] = evidence


def derive_scoring_inputs(record: dict, lifecycle: dict, takeover: dict,
                          today: date | None = None) -> None:
    """Everything the rules need beyond the Phase 1 enrichment."""
    derive_lifecycle(record, lifecycle, today)
    derive_takeover(record, takeover)

    # Convenience aliases the rules read, so a rule condition stays readable.
    record["auth_surface"] = record.get("auth_surface_type", "none") != "none"
    record["auth_required"] = (
        record.get("response_class") == "auth_required"
        or record.get("status_code") == 401
    )
