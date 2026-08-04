"""Data-quality census and scan-completeness checks.

Two jobs:

1. Per-column fill rates, which drive the UI's auto-hiding of empty columns.
   That makes today's 21 empty columns a non-issue *and* makes them appear
   automatically the day a richer httpx flag set is used — no code change.
2. Guarding against ingesting a scan that is still running. A truncated scan
   becomes a permanent fake "everything improved" dip in the trendline, and it
   is very hard to spot after the fact.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from . import schema

# A file whose newest observation is this recent was probably still being
# written when we read it.
FRESH_SECONDS = 180


def column_census(raw_rows: list[dict], columns: list[str]) -> list[dict]:
    total = len(raw_rows)
    out: list[dict] = []
    for name in columns:
        non_empty = 0
        sample = ""
        for row in raw_rows:
            value = row.get(name)
            text = "" if value is None else str(value).strip()
            if text and text.lower() not in ("null", "[]", "false", "n/a"):
                non_empty += 1
                if not sample:
                    sample = text[:120]
        out.append({
            "column_name": name,
            "non_empty": non_empty,
            "total": total,
            "fill_pct": round(100.0 * non_empty / total, 2) if total else 0.0,
            "sample": sample,
        })
    return out


def completeness_check(records: list[dict], *, source_mtime: float | None = None,
                       previous_ports: set[int] | None = None,
                       supervised: bool = False) -> list[str]:
    """Return human-readable warnings; empty means the scan looks complete.

    `supervised` means we started the scanner and watched it exit, so completeness
    is a fact rather than an inference. Both freshness heuristics are then skipped:
    a scan that just finished necessarily has second-old observations, so they
    could only ever produce a false positive. The port-subset check still applies —
    that catches a narrower profile, which is real regardless of who ran it.
    """
    warnings: list[str] = []
    if not records:
        return ["file contained no usable records"]

    data_is_fresh: bool | None = None
    stamps = [] if supervised else [
        r.get("scanned_at") for r in records if r.get("scanned_at")]
    if stamps:
        newest_text = max(stamps)
        try:
            newest = datetime.fromisoformat(newest_text)
            if newest.tzinfo is None:
                newest = newest.replace(tzinfo=UTC)
            age = (datetime.now(UTC) - newest).total_seconds()
            data_is_fresh = age < FRESH_SECONDS
            if data_is_fresh:
                warnings.append(
                    f"newest observation is only {int(age)}s old — the scan may "
                    f"still be running, which would truncate this run"
                )
        except ValueError:
            pass

    # A recent mtime only means "still being written" if the OBSERVATIONS are also
    # recent. A file whose newest row is a month old but which was modified a
    # moment ago was copied, checked out, or downloaded — `git clone` stamps every
    # file with the clone time, which made the documented first command fail on
    # every fresh checkout.
    if source_mtime is not None and data_is_fresh is not False and not supervised:
        age = datetime.now(UTC).timestamp() - source_mtime
        if age < FRESH_SECONDS:
            warnings.append(
                f"source file was modified {int(age)}s ago — it may still be "
                f"being written"
            )

    ports = {int(r["port"]) for r in records}
    if previous_ports and ports < previous_ports:
        missing = sorted(previous_ports - ports)
        warnings.append(
            f"this run probed fewer ports than the previous one — missing "
            f"{missing}. A partial scan will read as a false improvement."
        )

    return warnings


def drift_check(endpoint_count: int, previous_count: int | None,
                threshold_pct: float = 30.0) -> str | None:
    """Catch a truncated or partial scan before it lands in the trendline."""
    if not previous_count:
        return None
    delta = abs(endpoint_count - previous_count)
    pct = 100.0 * delta / previous_count
    if pct > threshold_pct:
        direction = "more" if endpoint_count > previous_count else "fewer"
        return (
            f"endpoint count changed by {pct:.0f}% ({previous_count} -> "
            f"{endpoint_count}, {direction})"
        )
    return None


def truncation_check(
    endpoint_count: int,
    previous_count: int | None,
    *,
    hosts_submitted: int | None,
    previous_hosts_submitted: int | None,
    ports_prescoped: int | None,
    previous_ports_prescoped: int | None,
    threshold_pct: float = 30.0,
    host_tolerance_pct: float = 10.0,
) -> tuple[str | None, bool]:
    """Like `drift_check`, but for a scan (not an upload) it also knows how
    many hosts were actually submitted to httpx this run and last — which is
    what tells a truncated run (same host list, far fewer rows because httpx
    died partway through) apart from a legitimately different one (a bigger
    or smaller portfolio, or a port-profile change).

    Returns `(warning, is_suspected_truncation)`. `is_suspected_truncation`
    means this needs the `confirm_truncation` override, distinct from
    `allow_drift` — the whole reason this function exists is that a blanket
    `allow_drift=True` was silently swallowing exactly this case.
    """
    if hosts_submitted is None or previous_hosts_submitted is None:
        # Upload, or a run ingested before this signal existed — no host-list
        # signal available, so fall back to the plain count-only check.
        return drift_check(endpoint_count, previous_count, threshold_pct), False

    if not previous_count or not previous_hosts_submitted:
        return None, False

    delta_pct = 100.0 * abs(endpoint_count - previous_count) / previous_count
    if delta_pct <= threshold_pct:
        return None, False

    direction = "more" if endpoint_count > previous_count else "fewer"
    headline = (
        f"endpoint count changed by {delta_pct:.0f}% ({previous_count} -> "
        f"{endpoint_count}, {direction})"
    )

    if (ports_prescoped is not None and previous_ports_prescoped is not None
            and bool(ports_prescoped) != bool(previous_ports_prescoped)):
        # A known, explained cause of a different count — not a silent
        # truncation, so this is informative rather than blocking.
        naabu_note = (
            "naabu scoped ports this run but fell back to the full profile "
            "last time" if ports_prescoped else
            "naabu fell back to the full port profile this run, unlike the "
            "last one"
        )
        return f"{headline} — {naabu_note}; this alone can explain the swing", False

    host_delta_pct = (100.0 * abs(hosts_submitted - previous_hosts_submitted)
                      / previous_hosts_submitted)
    if host_delta_pct > host_tolerance_pct:
        # A genuinely different target list legitimately changes the count.
        return (f"{headline} — the target list also changed "
                f"({previous_hosts_submitted} -> {hosts_submitted} hosts submitted)"), False

    return (
        f"{headline} while submitting essentially the same "
        f"{hosts_submitted} host(s) as last time ({previous_hosts_submitted}) "
        f"— this looks like a truncated run, not a real change"
    ), True


def suggest_httpx_flags(census: list[dict]) -> list[dict[str, Any]]:
    """Recommend flags based on which columns are actually empty.

    The honest and useful answer to "why are 21 of 53 columns blank".
    """
    fill = {c["column_name"]: c["fill_pct"] for c in census}
    present = set(fill)
    suggestions: list[dict[str, Any]] = []

    for flag, columns in schema.FLAG_HINTS.items():
        relevant = [c for c in columns if c in present]
        if columns and relevant and all(fill.get(c, 0.0) == 0.0 for c in relevant):
            suggestions.append({
                "flag": flag,
                "empty_columns": relevant,
                "unlocks": schema.FLAG_UNLOCKS.get(flag, ""),
            })
        elif not columns and flag not in present:
            suggestions.append({
                "flag": flag,
                "empty_columns": [],
                "unlocks": schema.FLAG_UNLOCKS.get(flag, ""),
            })

    return suggestions


def recommended_command(census: list[dict]) -> str:
    flags = " ".join(s["flag"] for s in suggest_httpx_flags(census))
    base = "httpx -l hosts.txt -json -follow-redirects -sc -cl -title -tech-detect -cdn -ip -web-server"
    return f"{base} {flags}".strip()
