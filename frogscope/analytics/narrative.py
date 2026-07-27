"""Plain-English narrative generation.

Templates, not an LLM: the output has to be reproducible, auditable, and
identical for identical data. Every sentence is derived from a number that is
also shown on the page, so a reader can always check the claim.

The register is deliberately flat. No "critical exposure detected" — just what
was found, how much of it there is, and what it means. Overstatement is the main
way a security report loses its audience.
"""

from __future__ import annotations

from typing import Any


def _plural(count: int, singular: str, plural: str | None = None) -> str:
    return singular if count == 1 else (plural or f"{singular}s")


def _pct(part: int, whole: int) -> int:
    return int(round(100 * part / whole)) if whole else 0


def headline(exec_data: dict[str, Any]) -> str:
    """One sentence stating the size of the job."""
    posture = exec_data["posture"]
    total = posture["total_hosts"]
    attention = posture["needs_attention"]

    if not total:
        return "No hosts were found in this scan."
    if not attention:
        return (
            f"None of the {total} {_plural(total, 'host')} reviewed has a "
            f"critical or high-severity finding."
        )
    return (
        f"{attention} of {total} {_plural(total, 'host')} "
        f"({_pct(attention, total)}%) have at least one critical or "
        f"high-severity finding."
    )


def verdict(exec_data: dict[str, Any]) -> str:
    """A second sentence putting the headline in proportion."""
    posture = exec_data["posture"]
    buckets = posture["by_worst_finding"]
    critical = buckets.get("critical", 0)
    clean = posture["clean"]
    total = posture["total_hosts"] or 1

    parts: list[str] = []
    if critical:
        parts.append(
            f"{critical} {_plural(critical, 'host')} "
            f"{_plural(critical, 'carries', 'carry')} a critical issue and "
            f"should be looked at first"
        )
    if clean:
        parts.append(
            f"{clean} {_plural(clean, 'host')} "
            f"({_pct(clean, total)}%) had nothing flagged at all"
        )
    if not parts:
        return ""
    return ". ".join(p[0].upper() + p[1:] for p in parts) + "."


def scale_note(exec_data: dict[str, Any]) -> str:
    """Explain the difference between what was probed and what actually exists.

    Without this the reader compares a probe count against a host count and
    concludes the estate is far larger than it is.
    """
    surface = exec_data["surface"]
    probed = surface["endpoints"]
    real = surface["real_endpoints"]
    artefacts = surface["scan_artifacts"]
    aliases = surface["cf_alias_ports"]

    if not probed or real == probed:
        return (
            f"The scan probed {probed} {_plural(probed, 'endpoint')} across "
            f"{surface['hosts']} {_plural(surface['hosts'], 'host')}."
        )

    return (
        f"The scan probed {probed} host-and-port combinations, but only {real} "
        f"are distinct services. {aliases} are Cloudflare proxy aliases of a site "
        f"already counted, and {artefacts} are artefacts of probing a TLS-only "
        f"port over plain HTTP. Counting those would overstate the surface by "
        f"roughly {probed // max(1, real)}x."
    )


def protection_note(exec_data: dict[str, Any]) -> str:
    protection = exec_data["protection"]
    segments = {s["key"]: s for s in protection["segments"]}
    waf = segments.get("waf", {})
    platform = segments.get("platform", {})
    nothing = segments.get("none", {})

    sentences: list[str] = []
    if waf.get("count"):
        sentences.append(
            f"{waf['pct']}% of real endpoints sit behind a WAF or CDN that "
            f"inspects traffic"
        )
    if platform.get("count"):
        sentences.append(
            f"{platform['pct']}% run on a managed platform that proxies traffic "
            f"but does not filter attacks"
        )
    if nothing.get("count"):
        sentences.append(
            f"{nothing['count']} {_plural(nothing['count'], 'endpoint')} "
            f"{_plural(nothing['count'], 'is', 'are')} reached directly with "
            f"nothing in front"
        )
    if not sentences:
        return ""
    return ". ".join(s[0].upper() + s[1:] for s in sentences) + "."


def theme_sentences(exec_data: dict[str, Any], limit: int = 6) -> list[dict[str, Any]]:
    """The main problems as plain statements, worst and most widespread first."""
    out: list[dict[str, Any]] = []
    for theme in exec_data["themes"][:limit]:
        hosts = theme["hosts"]
        line = theme["exec_line"].strip()
        if line and not line.endswith("."):
            line += "."
        sentence = (
            f"{hosts} {_plural(hosts, 'host')}: {line[0].lower() + line[1:]}"
            if line else f"{hosts} {_plural(hosts, 'host')} affected."
        )
        note = ""
        if theme["confidence"] == "possible":
            note = ("Detected by fingerprint, so this flags something worth "
                    "checking rather than a confirmed weakness.")
        elif theme["confidence"] == "probable":
            note = "Strongly indicated, though not directly confirmed."

        out.append({
            "rule_id": theme["rule_id"],
            "severity": theme["severity"],
            "hosts": hosts,
            "sentence": sentence,
            "confidence_note": note,
            "remediation": theme["remediation"],
        })
    return out


def eol_note(exec_data: dict[str, Any]) -> str:
    eol = exec_data["eol"]
    if not eol["products"]:
        return ""
    worst = eol["products"][0]
    hosts = eol["host_count"]

    if worst.get("years_past_eol"):
        years = int(worst["years_past_eol"])
        return (
            f"{hosts} {_plural(hosts, 'host')} run software the vendor no longer "
            f"supports. The oldest is {worst['name']}, unsupported for about "
            f"{years} {_plural(years, 'year')} — no security patches are issued "
            f"for it, and no configuration change makes it safe."
        )
    return (
        f"{hosts} {_plural(hosts, 'host')} run software with no current support "
        f"commitment, including {worst['name']}."
    )


def concentration_note(exec_data: dict[str, Any]) -> str:
    zones = exec_data["by_zone"]
    if not zones:
        return ""
    top = zones[0]
    if not top["needs_attention"]:
        return ""
    total_attention = exec_data["posture"]["needs_attention"] or 1
    share = _pct(top["needs_attention"], total_attention)
    if share < 25:
        return (
            "The hosts needing attention are spread fairly evenly across the "
            "estate rather than concentrated in one area."
        )
    return (
        f"{share}% of the hosts needing attention sit in one group "
        f"({top['dimension']}), so work there would address the largest share "
        f"for the least effort."
    )


def nonprod_note(exec_data: dict[str, Any]) -> str:
    envs = {e["dimension"]: e for e in exec_data["by_env"]}
    nonprod = {k: v for k, v in envs.items()
               if k in ("dev", "test", "uat", "ta", "sit", "staging", "sandbox")}
    if not nonprod:
        return ""
    hosts = sum(v["hosts"] for v in nonprod.values())
    attention = sum(v["needs_attention"] for v in nonprod.values())
    names = ", ".join(sorted(nonprod))
    sentence = (
        f"{hosts} {_plural(hosts, 'host')} are identifiably non-production "
        f"({names}) and reachable from the internet"
    )
    if attention:
        sentence += (
            f", of which {attention} {_plural(attention, 'has', 'have')} a "
            f"critical or high finding. Non-production systems often carry real "
            f"data with weaker controls"
        )
    return sentence + "."


def unclassified_note(exec_data: dict[str, Any]) -> str:
    """Flag weak environment classification rather than hiding it.

    Environment is inferred from hostname tokens. When most hosts do not match
    one, any per-environment cut is close to meaningless and the reader should
    know that before drawing conclusions from it.
    """
    envs = {e["dimension"]: e for e in exec_data["by_env"]}
    unclassified = envs.get("unclassified")
    total = exec_data["posture"]["total_hosts"] or 1
    if not unclassified:
        return ""
    share = _pct(unclassified["hosts"], total)
    if share < 40:
        return ""
    return (
        f"{share}% of hosts could not be assigned an environment from their "
        f"name, so the split by environment covers only the remainder. Adding "
        f"naming rules to config/classify.yaml, or an ownership register, would "
        f"make that cut meaningful."
    )


def build(exec_data: dict[str, Any]) -> dict[str, Any]:
    """Assemble the narrative. Every claim traces to a number on the page."""
    notes = [
        scale_note(exec_data),
        protection_note(exec_data),
        eol_note(exec_data),
        nonprod_note(exec_data),
        concentration_note(exec_data),
        unclassified_note(exec_data),
    ]
    return {
        "headline": headline(exec_data),
        "verdict": verdict(exec_data),
        "notes": [n for n in notes if n],
        "themes": theme_sentences(exec_data),
    }
