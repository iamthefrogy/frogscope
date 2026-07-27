"""Read httpx output into canonical records.

Accepts CSV, TSV, JSON array, and JSONL. httpx's ``-json`` output carries more
fields than ``-csv`` for the same scan, and since the field mapping is
alias-driven both converge on the same canonical records.
"""

from __future__ import annotations

import csv
import gzip
import hashlib
import io
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import schema
from .normalize import (
    norm_host,
    parse_bool,
    parse_duration_ms,
    parse_int,
    parse_json_array,
    parse_timestamp,
)

# httpx rows can carry very long final_url values (OAuth redirects run to
# several KB), which trips csv's default field-size ceiling.
csv.field_size_limit(min(sys.maxsize, 2**31 - 1))


@dataclass
class LoadResult:
    records: list[dict]
    source_columns: list[str]
    missing_columns: list[str] = field(default_factory=list)
    unknown_columns: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    raw_sha256: str = ""
    byte_count: int = 0
    row_count: int = 0
    fmt: str = ""


def _open(path: Path) -> io.TextIOBase:
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace", newline="")
    return path.open("r", encoding="utf-8", errors="replace", newline="")


def _sniff_format(path: Path, sample: str) -> str:
    stem = path.name.lower().removesuffix(".gz")
    head = sample.lstrip()
    if head.startswith("["):
        return "json"
    if head.startswith("{"):
        return "jsonl"
    if stem.endswith(".tsv") or "\t" in sample.split("\n", 1)[0]:
        return "tsv"
    return "csv"


def _raw_rows(path: Path) -> tuple[list[dict], list[str], str]:
    with _open(path) as fh:
        sample = fh.read(65536)
        fh.seek(0)
        fmt = _sniff_format(path, sample)

        if fmt == "json":
            data = json.load(fh)
            rows = data if isinstance(data, list) else [data]
        elif fmt == "jsonl":
            rows = []
            for line in fh:
                line = line.strip()
                if line:
                    rows.append(json.loads(line))
        else:
            delimiter = "\t" if fmt == "tsv" else ","
            reader = csv.DictReader(fh, delimiter=delimiter)
            rows = list(reader)

    if not rows:
        return [], [], fmt

    if fmt in ("json", "jsonl"):
        seen: list[str] = []
        for row in rows:
            for key in row:
                if key not in seen:
                    seen.append(key)
        columns = seen
    else:
        columns = list(rows[0].keys())

    return rows, columns, fmt


def _flatten(row: dict, prefix: str = "") -> dict:
    """httpx -json nests wordpress plugins; -csv flattens to 'wordpress.Plugins'."""
    out: dict[str, Any] = {}
    for key, value in row.items():
        name = f"{prefix}{key}"
        if isinstance(value, dict):
            out.update(_flatten(value, f"{name}."))
        else:
            out[name] = value
    return out


def load(path: Path | str) -> LoadResult:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(path)

    digest = hashlib.sha256()
    byte_count = 0
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
            byte_count += len(chunk)

    raw_rows, columns, fmt = _raw_rows(path)
    result = LoadResult(
        records=[],
        source_columns=columns,
        raw_sha256=digest.hexdigest(),
        byte_count=byte_count,
        row_count=len(raw_rows),
        fmt=fmt,
    )

    if not raw_rows:
        result.warnings.append("file contains no data rows")
        return result

    known = set(schema.HTTPX_COLUMNS)
    present = set(columns)
    if not (present & set(schema.REQUIRED_ANY)):
        raise ValueError(
            "this does not look like httpx output — expected at least one of "
            f"{schema.REQUIRED_ANY}, found columns: {columns[:12]}"
        )

    result.missing_columns = sorted(known - present)
    result.unknown_columns = sorted(present - known)

    for index, raw in enumerate(raw_rows):
        flat = _flatten(raw) if fmt in ("json", "jsonl") else dict(raw)
        rec = _to_record(flat, index, result.warnings)
        if rec is not None:
            result.records.append(rec)

    return result


_IPV4_ONLY = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _looks_like_address(value: str) -> bool:
    """True for a bare IPv4 or bracketed IPv6 literal."""
    text = str(value or "").strip().strip("[]")
    return bool(_IPV4_ONLY.match(text)) or (":" in text and "." not in text)


def _host_from(flat: dict) -> str:
    """The NAME this endpoint is known by, preferring a hostname over an address.

    httpx's `host` column holds the RESOLVED ADDRESS, while `input` holds the name
    that was probed. Trusting `host` keyed every endpoint on an IP, which breaks
    everything downstream: identity rotates with round-robin DNS, so every scan
    reports the whole estate as new, and the zone and registrable-domain
    derivations turn `104.20.21.8` into the nonsense domain `21.8`.
    """
    candidates = []
    # The URL is authoritative — it is literally scheme://authority — followed by
    # the input that was given to the scanner.
    if flat.get("url"):
        authority = str(flat["url"]).split("//", 1)[-1].split("/", 1)[0]
        candidates.append(authority)
    candidates.append(flat.get("input") or "")
    candidates.append(flat.get("host") or "")

    for candidate in candidates:
        text = str(candidate or "").strip()
        if text and not _looks_like_address(text.rsplit(":", 1)[0]):
            return text
    # Everything available is an address. Use it rather than dropping the row: an
    # endpoint probed by address is still a real endpoint.
    return next((str(c) for c in candidates if str(c or "").strip()), "")


def _to_record(flat: dict, index: int, warnings: list[str]) -> dict | None:
    host_raw = _host_from(flat)

    host, host_display = norm_host(host_raw)
    if not host:
        warnings.append(f"row {index}: no resolvable host, skipped")
        return None

    port = parse_int(flat.get("port"))
    if port is None:
        scheme_hint = str(flat.get("scheme") or "").lower()
        port = 443 if scheme_hint == "https" else 80
        warnings.append(f"row {index}: missing port, inferred {port}")

    scheme = (str(flat.get("scheme") or "").lower()
              or ("https" if port == 443 else "http"))

    # httpx's `host` column is the resolved address. It is no longer the identity,
    # but it is still the answering address, which the blast-radius and
    # concentration analysis both rely on.
    answered_from = str(flat.get("host") or "").strip()

    rec: dict[str, Any] = {
        "endpoint_key": f"{host}:{port}",
        "host": host,
        "host_display": host_display,
        "port": port,
        "scheme": scheme,
        "input_raw": flat.get("input") or "",
        "answered_from": answered_from if _looks_like_address(answered_from) else "",
        "path": flat.get("path") or "/",
        "method": flat.get("method") or "GET",
        "source_row": index,

        "status_code": parse_int(flat.get("status_code")),
        "title": (flat.get("title") or "").strip(),
        "content_type": (flat.get("content_type") or "").strip(),
        "content_length": parse_int(flat.get("content_length")),
        "words": parse_int(flat.get("words")),
        "lines": parse_int(flat.get("lines")),
        "response_ms": parse_duration_ms(flat.get("time")),
        "webserver": (flat.get("webserver") or "").strip(),

        "final_url": (flat.get("final_url") or "").strip(),
        "location": (flat.get("location") or "").strip(),
        "redirect_chain": [
            c for c in parse_json_array(flat.get("chain_status_codes"),
                                        warnings, "chain_status_codes")
            if isinstance(c, int)
        ],

        "host_ip": (flat.get("host_ip") or "").strip(),
        "a": [str(x) for x in parse_json_array(flat.get("a"), warnings, "a")],
        "aaaa": [str(x) for x in parse_json_array(flat.get("aaaa"), warnings, "aaaa")],
        "cname": [str(x).rstrip(".").lower()
                  for x in parse_json_array(flat.get("cname"), warnings, "cname")],
        "resolvers": [str(x) for x in
                      parse_json_array(flat.get("resolvers"), warnings, "resolvers")],

        "cdn": parse_bool(flat.get("cdn")),
        "cdn_name": (flat.get("cdn_name") or "").strip(),
        "cdn_type": (flat.get("cdn_type") or "").strip(),

        "tech": [str(x) for x in parse_json_array(flat.get("tech"), warnings, "tech")],
        "cpe": parse_json_array(flat.get("cpe"), warnings, "cpe"),
        "wp_plugins": [
            str(x) for x in
            parse_json_array(flat.get("wordpress.Plugins"), warnings, "wordpress.Plugins")
        ],
        "wp_themes": [
            str(x) for x in
            parse_json_array(flat.get("wordpress.Themes"), warnings, "wordpress.Themes")
        ],

        "scanned_at": parse_timestamp(flat.get("timestamp")),
        "failed": parse_bool(flat.get("failed")),
        "error": (flat.get("error") or "").strip(),

        # Reserved — present so a richer future run needs no schema change.
        "body_preview": (flat.get("body_preview") or "").strip(),
        "jarm_hash": (flat.get("jarm_hash") or "").strip(),
        "favicon_md5": (flat.get("favicon_md5") or "").strip(),
        "screenshot_path": (flat.get("screenshot_path") or "").strip(),
        "tls_version": (flat.get("tls_version") or flat.get("tls.version") or "").strip(),
        "cert_issuer": (flat.get("cert_issuer") or flat.get("tls.issuer_cn") or "").strip(),
        "cert_not_after": (flat.get("cert_not_after") or flat.get("tls.not_after") or "").strip(),
        "asn": (flat.get("asn") or flat.get("asn.as_number") or "").strip(),
        "asn_org": (flat.get("asn_org") or flat.get("asn.as_name") or "").strip(),
    }

    # cpe arrives as [{product, vendor, cpe}]; flatten to vendor:product keys.
    products: list[str] = []
    for entry in rec["cpe"]:
        if isinstance(entry, dict):
            vendor = str(entry.get("vendor") or "").strip()
            product = str(entry.get("product") or "").strip()
            if vendor or product:
                products.append(f"{vendor}:{product}")
        elif entry:
            products.append(str(entry))
    rec["cpe_products"] = products

    known = set(schema.HTTPX_COLUMNS)
    rec["raw"] = dict(flat.items())
    rec["extra"] = {k: v for k, v in flat.items() if k not in known}
    return rec
