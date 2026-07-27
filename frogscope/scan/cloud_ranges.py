"""Fetch and cache public cloud provider IP ranges.

Lives here, not in `frogscope/ingest/`, because it makes an outbound HTTP
request — and per the project's own house rule (see README "Contributing"),
`frogscope/scan/` and `frogscope/verify/` are the only modules allowed to
touch the network. `ingest/correlate.py` only ever reads the JSON file this
module writes; it never fetches anything itself.

Why this exists at all: `config/cloud_ranges.yaml` explains the full
reasoning — asnmap/dnsx-asn/mapcidr's ASN input all require a ProjectDiscovery
API key, which this release does not depend on, so "which cloud provider owns
this address" is instead answered from each provider's own public,
versioned, no-key-required range feed.

Only AWS, GCP, and DigitalOcean are implemented — all three publish a stable
direct-URL feed in a fixed, parseable shape (verified against the real feeds:
see the field paths this mirrors in `config/cloud_ranges.yaml`). Azure
publishes its current feed only behind a versioned download-page link that
changes every release and needs HTML scraping to resolve — a documented gap
is better than a fragile scraper, so it is skipped with a clear reason rather
than guessed at.
"""

from __future__ import annotations

import csv
import io
import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

USER_AGENT = "frogscope (+https://github.com/frogy/frogscope)"
FETCH_TIMEOUT = 20
SUPPORTED_FORMATS = ("aws_ip_ranges_json", "gcp_cloud_json", "csv_cidr_first_column")


@dataclass
class FetchResult:
    provider_id: str
    ok: bool
    cidr_count: int = 0
    skip_reason: str = ""
    error: str = ""


def _fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as resp:  # noqa: S310
        return resp.read().decode("utf-8", errors="replace")


def _parse_aws(text: str) -> list[str]:
    data = json.loads(text)
    cidrs = [p["ip_prefix"] for p in data.get("prefixes", []) if p.get("ip_prefix")]
    cidrs += [p["ipv6_prefix"] for p in data.get("ipv6_prefixes", []) if p.get("ipv6_prefix")]
    return cidrs


def _parse_gcp(text: str) -> list[str]:
    data = json.loads(text)
    cidrs = []
    for p in data.get("prefixes", []):
        cidrs.append(p.get("ipv4Prefix") or p.get("ipv6Prefix"))
    return [c for c in cidrs if c]


def _parse_csv_first_column(text: str) -> list[str]:
    reader = csv.reader(io.StringIO(text))
    return [row[0].strip() for row in reader if row and row[0].strip()]


_PARSERS = {
    "aws_ip_ranges_json": _parse_aws,
    "gcp_cloud_json": _parse_gcp,
    "csv_cidr_first_column": _parse_csv_first_column,
}


def refresh(providers: list[dict[str, Any]], cache_path: Path,
           *, force: bool = False, ttl_hours: float = 24) -> dict[str, Any]:
    """Fetch every supported provider's feed and write the cache file.

    Returns the cache dict (same shape written to disk), so a caller — the
    scan runner — can report per-provider outcomes in `run_collectors`
    without a second read of the file it just wrote.
    """
    now = datetime.now(UTC)
    existing: dict[str, Any] = {}
    if cache_path.exists() and not force:
        try:
            existing = json.loads(cache_path.read_text(encoding="utf-8"))
            fetched_at = datetime.fromisoformat(existing.get("fetched_at", ""))
            age_hours = (now - fetched_at).total_seconds() / 3600
            if age_hours < ttl_hours:
                return existing
        except (ValueError, OSError, json.JSONDecodeError):
            existing = {}

    out: dict[str, Any] = {"fetched_at": now.isoformat(), "providers": {}}
    for provider in providers:
        pid = provider["id"]
        fmt = provider.get("format")
        if fmt not in SUPPORTED_FORMATS:
            out["providers"][pid] = {
                "cidrs": [], "count": 0,
                "skip_reason": f"format {fmt!r} not yet automated — needs a "
                               f"resolved download link, not a stable URL",
            }
            continue
        try:
            text = _fetch(provider["url"])
            cidrs = _PARSERS[fmt](text)
        except (urllib.error.URLError, OSError, json.JSONDecodeError, ValueError) as exc:
            out["providers"][pid] = {
                "cidrs": [], "count": 0,
                "skip_reason": f"fetch failed: {exc}",
            }
            continue
        out["providers"][pid] = {"cidrs": cidrs, "count": len(cidrs), "skip_reason": ""}

    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(json.dumps(out), encoding="utf-8")
    return out
