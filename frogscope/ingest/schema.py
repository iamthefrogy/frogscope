"""Canonical field registry for httpx output.

Deliberately tolerant in both directions:

* A **missing** source column yields a null field and is recorded, never raised.
  Different httpx flag sets produce different column sets, and 21 of the 53
  columns in a plain ``-csv`` run are entirely empty.
* An **unknown** source column is preserved verbatim into ``extra`` and
  surfaced in the Coverage view as "a new httpx field is available", rather
  than being dropped.

That combination is what makes a future ``-tls-grab`` or ``-screenshot`` run
light up automatically instead of needing a code change.
"""

from __future__ import annotations

from typing import NamedTuple


class Field(NamedTuple):
    canonical: str
    kind: str            # str int float bool list objlist datetime duration host
    group: str
    reserved: bool = False   # expected empty until richer httpx flags are used


# source httpx column -> canonical field
HTTPX_COLUMNS: dict[str, Field] = {
    # identity
    "host":            Field("host", "host", "identity"),
    "input":           Field("input_raw", "str", "identity"),
    "port":            Field("port", "int", "identity"),
    "scheme":          Field("scheme", "str", "identity"),
    "url":             Field("source_url", "str", "identity"),
    "path":            Field("path", "str", "identity"),
    "method":          Field("method", "str", "identity"),

    # response
    "status_code":     Field("status_code", "int", "response"),
    "title":           Field("title", "str", "response"),
    "content_type":    Field("content_type", "str", "response"),
    "content_length":  Field("content_length", "int", "response"),
    "words":           Field("words", "int", "response"),
    "lines":           Field("lines", "int", "response"),
    "time":            Field("response_ms", "duration", "response"),
    "webserver":       Field("webserver", "str", "response"),
    "body_preview":    Field("body_preview", "str", "response", reserved=True),

    # redirect
    "final_url":          Field("final_url", "str", "redirect"),
    "location":           Field("location", "str", "redirect"),
    "chain_status_codes": Field("redirect_chain", "list", "redirect"),

    # dns
    "host_ip":   Field("host_ip", "str", "dns"),
    "a":         Field("a", "list", "dns"),
    "aaaa":      Field("aaaa", "list", "dns"),
    "cname":     Field("cname", "list", "dns"),
    "resolvers": Field("resolvers", "list", "dns"),

    # edge
    "cdn":       Field("cdn", "bool", "infra"),
    "cdn_name":  Field("cdn_name", "str", "infra"),
    "cdn_type":  Field("cdn_type", "str", "infra"),
    "vhost":     Field("vhost", "bool", "infra", reserved=True),
    "http2":     Field("http2", "bool", "infra", reserved=True),
    "pipeline":  Field("pipeline", "bool", "infra", reserved=True),
    "websocket": Field("websocket", "bool", "infra", reserved=True),

    # technology
    "tech":               Field("tech", "list", "fingerprint"),
    "cpe":                Field("cpe", "objlist", "fingerprint"),
    "wordpress.Plugins":  Field("wp_plugins", "list", "fingerprint"),
    "wordpress.Themes":   Field("wp_themes", "list", "fingerprint"),

    # reserved — need -tls-grab / -jarm / -favicon / -screenshot / -asn
    "sni":                  Field("sni", "str", "tls", reserved=True),
    "jarm_hash":            Field("jarm_hash", "str", "tls", reserved=True),
    "favicon":              Field("favicon", "str", "fingerprint", reserved=True),
    "favicon_md5":          Field("favicon_md5", "str", "fingerprint", reserved=True),
    "favicon_path":         Field("favicon_path", "str", "fingerprint", reserved=True),
    "favicon_url":          Field("favicon_url", "str", "fingerprint", reserved=True),
    "screenshot_bytes":     Field("screenshot_bytes", "int", "response", reserved=True),
    "screenshot_path":      Field("screenshot_path", "str", "response", reserved=True),
    "screenshot_path_rel":  Field("screenshot_path_rel", "str", "response", reserved=True),
    "headless_body":        Field("headless_body", "str", "response", reserved=True),
    "stored_response_path": Field("stored_response_path", "str", "provenance", reserved=True),
    "body_fqdn":            Field("body_fqdn", "list", "response", reserved=True),
    "body_domains":         Field("body_domains", "list", "response", reserved=True),
    "link_request":         Field("link_request", "str", "provenance", reserved=True),
    "extract_regex":        Field("extract_regex", "str", "provenance", reserved=True),

    # status / provenance
    "timestamp": Field("scanned_at", "datetime", "provenance"),
    "failed":    Field("failed", "bool", "provenance"),
    "error":     Field("error", "str", "provenance"),
}

# Any one of these is enough to treat the file as httpx output.
REQUIRED_ANY = ("host", "url", "input")

# JSON-in-a-cell columns, for the array parser.
LIST_COLUMNS = tuple(
    src for src, f in HTTPX_COLUMNS.items() if f.kind in ("list", "objlist")
)

# Columns expected to be empty without richer flags. Used to build the
# "recommended httpx flags" suggestion rather than to hide anything.
FLAG_HINTS = {
    "-tls-grab":   ("sni", "jarm_hash"),
    "-jarm":       ("jarm_hash",),
    "-favicon":    ("favicon", "favicon_md5", "favicon_url"),
    "-screenshot": ("screenshot_path", "screenshot_bytes", "headless_body"),
    "-asn":        (),
    "-body-preview": ("body_preview",),
    "-store-response": ("stored_response_path",),
}

FLAG_UNLOCKS = {
    "-tls-grab": "TLS version, cipher, issuer, and certificate expiry — enables "
                 "the certificate-hygiene rules, which are written but inert.",
    "-jarm": "JARM TLS fingerprint — clusters hosts sharing a TLS stack.",
    "-favicon": "Favicon hash — clusters related applications and finds "
                "forgotten copies of a known app.",
    "-screenshot": "Page screenshots — enables a visual gallery and "
                   "screenshot-diffing between runs.",
    "-asn": "ASN and network owner — groups assets by hosting network.",
    "-body-preview": "Response body sample — improves login and error-page "
                     "classification.",
    "-store-response": "Full stored responses — enables offline re-analysis.",
}


def canonical_for(source_column: str) -> Field | None:
    return HTTPX_COLUMNS.get(source_column)


def reserved_fields() -> tuple[str, ...]:
    return tuple(f.canonical for f in HTTPX_COLUMNS.values() if f.reserved)
