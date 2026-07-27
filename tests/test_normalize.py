"""Tests for the three data traps.

Each of these silently corrupts the whole product if it regresses, and none of
them is obvious from reading the output — hence explicit tests rather than
eyeballing a dashboard.
"""

from __future__ import annotations

import pytest

from frogscope.ingest.normalize import (
    collapse_intra_run,
    content_hash,
    norm_host,
    parse_duration_ms,
    parse_json_array,
    registrable_domain,
    zone_of,
)

# ── Trap 1: mixed duration units ────────────────────────────────────────────

@pytest.mark.parametrize("text,expected", [
    ("752.536792ms", 752.536792),
    ("1.469752375s", 1469.752375),
    ("133.936333ms", 133.936333),
    ("1m30.5s", 90_500.0),
    ("2m", 120_000.0),
    ("1h", 3_600_000.0),
    ("500us", 0.5),
    ("500µs", 0.5),
    ("1000ns", 0.001),
    ("1h2m3s", 3_723_000.0),
])
def test_parse_duration_units(text, expected):
    assert parse_duration_ms(text) == pytest.approx(expected)


def test_minutes_are_not_confused_with_milliseconds():
    """The classic bug: a naive r'(\\d+)m' also matches the 'm' of 'ms'."""
    assert parse_duration_ms("5ms") == pytest.approx(5.0)
    assert parse_duration_ms("5m") == pytest.approx(300_000.0)
    assert parse_duration_ms("5ms") < parse_duration_ms("5m")


@pytest.mark.parametrize("text", ["", None, "null", "N/A", "-", "garbage"])
def test_parse_duration_rejects_junk(text):
    assert parse_duration_ms(text) is None


# ── Trap 2: hostname case and shape drift ───────────────────────────────────

def test_host_case_collapses_but_display_is_preserved():
    """Without this, every run reports the same asset as newly discovered."""
    upper, upper_display = norm_host("CFI.cl.example.com")
    lower, lower_display = norm_host("cfi.cl.example.com")
    assert upper == lower == "cfi.cl.example.com"
    assert upper_display == "CFI.cl.example.com"
    assert lower_display == "cfi.cl.example.com"


@pytest.mark.parametrize("raw,expected", [
    ("example.com.", "example.com"),           # trailing dot
    ("  Example.COM  ", "example.com"),        # whitespace and case
    ("example.com:8443", "example.com"),       # stray port
    ("[2606:4700::1]", "2606:4700::1"),        # bracketed IPv6
    ("[2606:4700::1]:443", "2606:4700::1"),
])
def test_host_normalisation_shapes(raw, expected):
    assert norm_host(raw)[0] == expected


def test_unicode_host_is_punycoded():
    assert norm_host("bücher.example.com")[0].startswith("xn--")


def test_zone_and_registrable_domain():
    assert registrable_domain("a.b.example.com") == "example.com"
    assert registrable_domain("a.b.example.co.uk", ("co.uk",)) == "example.co.uk"
    assert zone_of("adm.iem.example.com", "example.com") == "iem.example.com"
    assert zone_of("www.example.com", "example.com") == "direct"


# ── Trap 3: intra-run duplicate host:port rows ──────────────────────────────

def _rec(host, port, **kw):
    base = {
        "endpoint_key": f"{host}:{port}", "host": host, "port": port,
        "scheme": "https", "status_code": 200, "title": "", "webserver": "",
        "content_type": "", "cdn_name": "", "cdn_type": "", "final_url": "",
        "a": [], "aaaa": [], "cname": [], "resolvers": [], "tech": [],
        "cpe_products": [], "wp_plugins": [], "scanned_at": "2026-07-25T07:00:00+00:00",
    }
    base.update(kw)
    return base


def test_duplicate_host_port_rows_collapse_to_one():
    records = [
        _rec("a.example.com", 443, scanned_at="2026-07-25T07:00:00+00:00"),
        _rec("a.example.com", 443, scanned_at="2026-07-25T07:00:10+00:00"),
    ]
    out, report = collapse_intra_run(records)
    assert len(out) == 1
    assert out[0]["probe_count"] == 2
    assert report.duplicate_groups == 1
    assert report.duplicate_rows == 1


def test_latest_probe_wins():
    records = [
        _rec("a.example.com", 443, status_code=403,
             scanned_at="2026-07-25T07:00:00+00:00"),
        _rec("a.example.com", 443, status_code=200,
             scanned_at="2026-07-25T07:00:10+00:00"),
    ]
    out, _ = collapse_intra_run(records)
    assert out[0]["status_code"] == 200


def test_dns_records_are_unioned_not_overwritten():
    """The last probe undersamples a round-robin set. Taking only its records
    would show up as a false 'IP changed' on the next run."""
    records = [
        _rec("a.example.com", 443, a=["1.1.1.1"],
             scanned_at="2026-07-25T07:00:00+00:00"),
        _rec("a.example.com", 443, a=["2.2.2.2"],
             scanned_at="2026-07-25T07:00:10+00:00"),
    ]
    out, _ = collapse_intra_run(records)
    assert sorted(out[0]["a"]) == ["1.1.1.1", "2.2.2.2"]


def test_dns_variation_alone_is_not_flagged_as_inconsistent():
    records = [
        _rec("a.example.com", 443, a=["1.1.1.1"], host_ip="1.1.1.1",
             scanned_at="2026-07-25T07:00:00+00:00"),
        _rec("a.example.com", 443, a=["2.2.2.2"], host_ip="2.2.2.2",
             scanned_at="2026-07-25T07:00:10+00:00"),
    ]
    out, report = collapse_intra_run(records)
    assert out[0]["intra_run_inconsistent"] is False
    assert report.inconsistent_groups == 0


def test_meaningful_disagreement_is_flagged():
    records = [
        _rec("a.example.com", 443, status_code=200,
             scanned_at="2026-07-25T07:00:00+00:00"),
        _rec("a.example.com", 443, status_code=500,
             scanned_at="2026-07-25T07:00:10+00:00"),
    ]
    out, report = collapse_intra_run(records)
    assert out[0]["intra_run_inconsistent"] is True
    assert "status_code" in out[0]["inconsistent_fields"]
    assert report.inconsistent_groups == 1


def test_https_wins_a_scheme_conflict():
    records = [
        _rec("a.example.com", 8080, scheme="http",
             scanned_at="2026-07-25T07:00:10+00:00"),
        _rec("a.example.com", 8080, scheme="https",
             scanned_at="2026-07-25T07:00:00+00:00"),
    ]
    out, report = collapse_intra_run(records)
    assert out[0]["scheme"] == "https"
    assert out[0]["scheme_conflict"] is True
    assert report.scheme_conflicts == 1


# ── JSON array cells ────────────────────────────────────────────────────────

@pytest.mark.parametrize("raw,expected", [
    ("", []),
    ("null", []),          # httpx writes the literal string, not JSON null
    ("[]", []),
    ("N/A", []),
    (None, []),
    ('["a","b"]', ["a", "b"]),
    ("[302,200]", [302, 200]),
    ("['a','b']", ["a", "b"]),          # single-quoted pseudo-JSON
    ("bare", ["bare"]),
])
def test_parse_json_array(raw, expected):
    assert parse_json_array(raw) == expected


def test_unparseable_array_is_recorded_not_swallowed():
    warnings: list[str] = []
    assert parse_json_array('["broken', warnings, "tech") == []
    assert warnings and "tech" in warnings[0]


# ── Content hashing ─────────────────────────────────────────────────────────

def test_content_hash_ignores_row_order_and_volatile_fields():
    """So a re-export with reordered rows is recognised as a duplicate."""
    a = _rec("a.example.com", 443, scanned_at="2026-07-25T07:00:00+00:00")
    b = _rec("b.example.com", 443, scanned_at="2026-07-25T07:00:01+00:00")
    forward = content_hash([a, b])
    reverse = content_hash([b, a])
    assert forward == reverse

    later = dict(a, scanned_at="2026-07-26T09:00:00+00:00")
    assert content_hash([later, b]) == forward


def test_content_hash_changes_when_data_changes():
    a = _rec("a.example.com", 443)
    assert content_hash([a]) != content_hash([dict(a, status_code=500)])
