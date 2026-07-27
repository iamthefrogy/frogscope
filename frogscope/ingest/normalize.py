"""Parsing and normalisation of raw httpx rows.

Three traps in real httpx CSV output are handled here, and each one silently
corrupts the whole product if missed:

1. ``time`` mixes units — "752.536792ms" and "1.469752375s" in the same column,
   and Go emits composites like "1m30.5s".
2. Hostnames drift in case — "CFI.cl.example.com" and "cfi.cl.example.com" both
   appear. If the diff key is not lowercased, every run reports false new assets
   forever.
3. There are duplicate (host, port) rows *within a single run* — httpx re-probes
   some endpoints seconds apart. Left uncollapsed, every count is inflated and
   the diff engine sees phantom churn.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

# ── Duration ────────────────────────────────────────────────────────────────
# Go's time.Duration string form. The (?<![a-z]) guard and ordering matter:
# a naive r"(\d+)m" also matches the "m" of "ms".
_DUR_TOKEN = re.compile(r"(\d+(?:\.\d+)?)\s*(ns|µs|us|ms|s|m|h)", re.I)
_DUR_MULT = {
    "ns": 1e-6,
    "µs": 1e-3,
    "us": 1e-3,
    "ms": 1.0,
    "s": 1000.0,
    "m": 60_000.0,
    "h": 3_600_000.0,
}
# Longest-suffix-first so "ms" is consumed before "s", and "s" before "m" can
# mis-claim it.
_DUR_ORDER = ("ns", "µs", "us", "ms", "h", "m", "s")


def parse_duration_ms(value: Any) -> float | None:
    """'752.536792ms' -> 752.536792 · '1.469752375s' -> 1469.752375 · '1m30.5s' -> 90500.0"""
    if value is None:
        return None
    text = str(value).strip()
    if not text or text in ("null", "N/A", "-"):
        return None

    total = 0.0
    matched = False
    pos = 0
    while pos < len(text):
        ch = text[pos]
        if ch.isspace():
            pos += 1
            continue
        num_match = re.match(r"\d+(?:\.\d+)?", text[pos:])
        if not num_match:
            pos += 1
            continue
        number = float(num_match.group(0))
        pos += num_match.end()
        # Take the longest valid unit suffix at this position.
        unit = None
        for candidate in _DUR_ORDER:
            if text[pos:].lower().startswith(candidate.lower()):
                unit = candidate.lower()
                pos += len(candidate)
                break
        if unit is None:
            continue
        total += number * _DUR_MULT[unit]
        matched = True

    return total if matched else None


# ── JSON array cells ────────────────────────────────────────────────────────

def parse_json_array(value: Any, warnings: list[str] | None = None,
                     column: str = "") -> list:
    """Tolerant parse of httpx's JSON-in-a-cell columns.

    Handles '' / 'null' / '[]' -> [], proper JSON, single-quoted pseudo-JSON,
    and a bare scalar. Never raises; a genuine parse failure is recorded rather
    than swallowed, so it surfaces in the data-quality view.
    """
    if value is None:
        return []
    if isinstance(value, list):
        return value
    text = str(value).strip()
    if text in ("", "null", "[]", "N/A", "None"):
        return []

    if text[0] in "[{":
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            try:
                parsed = ast.literal_eval(text)
            except (ValueError, SyntaxError):
                if warnings is not None:
                    warnings.append(f"{column}: unparseable array {text[:80]!r}")
                return []
        if parsed is None:
            return []
        return parsed if isinstance(parsed, list) else [parsed]

    return [text]


def parse_int(value: Any) -> int | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text or text in ("null", "N/A", "-"):
        return None
    try:
        return int(float(text))
    except ValueError:
        return None


def parse_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("true", "1", "yes")


def parse_timestamp(value: Any) -> str | None:
    """Return a normalised ISO-8601 string, or None."""
    if not value:
        return None
    text = str(value).strip()
    if not text or text == "null":
        return None
    try:
        return datetime.fromisoformat(text).isoformat()
    except ValueError:
        return text


# ── Hostnames ───────────────────────────────────────────────────────────────

_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def norm_host(value: Any) -> tuple[str, str]:
    """Return (normalised, display).

    Normalised is lowercased, trailing-dot-stripped, punycoded, with any stray
    port removed. Display keeps the original casing so the UI can still show
    'CFI.cl.example.com' while the diff key stays stable.
    """
    raw = str(value or "").strip()
    display = raw
    host = raw

    if host.startswith("[") and "]" in host:          # [::1]:443
        host = host[1 : host.index("]")]
    elif host.count(":") == 1:
        head, _, tail = host.rpartition(":")
        if tail.isdigit():
            host = head

    host = host.rstrip(".").lower()
    if host and not host.isascii():
        try:
            host = host.encode("idna").decode("ascii")
        except (UnicodeError, ValueError):
            pass
    return host, display


def is_address(host: str) -> bool:
    """True when this "host" is an IP literal rather than a name."""
    text = str(host or "").strip().strip("[]")
    if _IPV4.match(text):
        return True
    # An IPv6 literal has colons and no dots (a dotted-quad tail would have been
    # caught above).
    return ":" in text and "." not in text


def registrable_domain(host: str, multi_label_tlds: Iterable[str] = ()) -> str:
    # An address has no registrable domain. Splitting one on dots produced the
    # nonsense domain "21.8" from 104.20.21.8, which then grouped unrelated hosts
    # together in every by-zone breakdown.
    if is_address(host):
        return host
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    for suffix in multi_label_tlds:
        if host.endswith("." + suffix):
            need = len(suffix.split(".")) + 1
            return ".".join(labels[-need:])
    return ".".join(labels[-2:])


def zone_of(host: str, root: str) -> str:
    """Everything after the leftmost label; 'direct' when that is the root."""
    if is_address(host):
        # Dropping the first octet of an address is meaningless. These are grouped
        # as what they are.
        return "ip-address"
    # The apex itself. Without this, example.com landed in the zone "com" — the
    # bare public suffix, which groups every unrelated .com host together.
    if host == root:
        return "direct"
    labels = host.split(".")
    if len(labels) <= 1:
        return host
    remainder = ".".join(labels[1:])
    if remainder == root:
        return "direct"
    return remainder


# ── Intra-run duplicate collapse ────────────────────────────────────────────

# Fields whose disagreement between repeat probes is meaningful. host_ip / a /
# aaaa are excluded on purpose: round-robin DNS legitimately differs between two
# probes seconds apart, and treating that as an inconsistency flags a large
# fraction of hosts for nothing.
SEMANTIC_FIELDS = (
    "status_code",
    "title",
    "webserver",
    "content_type",
    "cdn_name",
    "cdn_type",
    "scheme",
    "final_url",
)

# Union rather than last-write, because the last probe undersamples a
# round-robin record set — and undersampling directly causes false "IP changed"
# diffs on the next run.
UNION_FIELDS = ("a", "aaaa", "cname", "resolvers", "tech", "cpe_products", "wp_plugins")


@dataclass
class CollapseReport:
    input_rows: int = 0
    output_rows: int = 0
    duplicate_groups: int = 0
    duplicate_rows: int = 0
    inconsistent_groups: int = 0
    scheme_conflicts: int = 0
    group_size_hist: dict[int, int] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "input_rows": self.input_rows,
            "output_rows": self.output_rows,
            "duplicate_groups": self.duplicate_groups,
            "duplicate_rows": self.duplicate_rows,
            "inconsistent_groups": self.inconsistent_groups,
            "scheme_conflicts": self.scheme_conflicts,
            "group_size_hist": {str(k): v for k, v in sorted(self.group_size_hist.items())},
        }


def collapse_intra_run(records: list[dict]) -> tuple[list[dict], CollapseReport]:
    """Collapse to one record per (host, port).

    Winner is the latest probe, since the dashboard shows current state. List
    fields are unioned across the group.
    """
    report = CollapseReport(input_rows=len(records))
    groups: dict[tuple[str, int], list[dict]] = {}
    for rec in records:
        groups.setdefault((rec["host"], rec["port"]), []).append(rec)

    out: list[dict] = []
    for (_host, _port), group in groups.items():
        size = len(group)
        report.group_size_hist[size] = report.group_size_hist.get(size, 0) + 1

        if size == 1:
            winner = dict(group[0])
            winner["probe_count"] = 1
            winner["intra_run_inconsistent"] = False
            winner["inconsistent_fields"] = []
            winner["scheme_conflict"] = False
            out.append(winner)
            continue

        report.duplicate_groups += 1
        report.duplicate_rows += size - 1

        schemes = {r.get("scheme") for r in group}
        scheme_conflict = len(schemes) > 1
        if scheme_conflict:
            report.scheme_conflicts += 1
            # Prefer the https observation — it is the more capable listener.
            candidates = [r for r in group if r.get("scheme") == "https"] or group
        else:
            candidates = group

        winner = dict(max(candidates, key=lambda r: (r.get("scanned_at") or "")))

        inconsistent = [
            f for f in SEMANTIC_FIELDS if len({str(r.get(f)) for r in group}) > 1
        ]
        if inconsistent:
            report.inconsistent_groups += 1

        for f in UNION_FIELDS:
            merged: set = set()
            for r in group:
                merged.update(r.get(f) or [])
            # Sorted, so the union is deterministic regardless of the order the
            # group's rows happened to be read in. Without this the same scan
            # re-exported with reordered rows hashes differently, and the
            # duplicate check misses it.
            winner[f] = sorted(merged, key=str)

        winner["probe_count"] = size
        winner["intra_run_inconsistent"] = bool(inconsistent)
        winner["inconsistent_fields"] = inconsistent
        winner["scheme_conflict"] = scheme_conflict
        out.append(winner)

    out.sort(key=lambda r: r["endpoint_key"])
    report.output_rows = len(out)
    return out, report


# ── Hashing ─────────────────────────────────────────────────────────────────

def content_signature(rec: dict) -> str:
    """Groups template-identical endpoints without needing response bodies."""
    basis = "|".join(
        str(rec.get(k) or "")
        for k in ("status_code", "content_length", "words", "lines", "title")
    )
    return hashlib.sha1(basis.encode("utf-8", "replace")).hexdigest()[:12]


# Excluded from the content hash: values that change between two exports of the
# same scan without the findings changing. `source_row` is the position in the
# file, so reordering rows would otherwise defeat duplicate detection.
VOLATILE_FOR_HASH = frozenset({
    "scanned_at", "response_ms", "probe_count", "raw", "extra", "source_row",
})


def content_hash(records: list[dict]) -> str:
    """Order-independent hash over normalised records, excluding volatile fields.

    Lets us recognise "the same scan, re-exported with a different row or column
    order" as a duplicate, which a raw byte hash would miss.
    """
    digest = hashlib.sha256()
    for rec in sorted(records, key=lambda r: r["endpoint_key"]):
        stable = {}
        for key, value in sorted(rec.items()):
            if key in VOLATILE_FOR_HASH:
                continue
            # Lists are normalised so an incidental ordering difference is not
            # mistaken for a content difference.
            stable[key] = sorted(value, key=str) if isinstance(value, list) else value
        digest.update(
            json.dumps(stable, sort_keys=True, default=str).encode("utf-8", "replace")
        )
    return digest.hexdigest()
