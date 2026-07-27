"""Tests for the v2 correlation data traps.

Each of these was a real bug caught while building this against actual dnsx/
mapcidr/tlsx output (see tests/fixtures/correlation/README.md) — none of them
is obvious from eyeballing a dashboard, hence explicit tests.
"""

from __future__ import annotations

from pathlib import Path

from frogscope.ingest import correlate


def test_correlate_module_reaches_no_network():
    """This module reads the local cache `frogscope/scan/cloud_ranges.py`
    fetches — it must never touch the network itself. Per the README's
    "Nothing may send a packet during ingest" house rule, only
    `frogscope/scan/` and `frogscope/verify/` are allowed to."""
    source = Path(correlate.__file__).read_text(encoding="utf-8")
    for forbidden in ("urlopen", "urllib.request", "socket."):
        assert forbidden not in source, forbidden


# ── Trap 1: dnsx emits duplicate identical lines per host ───────────────────

def test_duplicate_dnsx_lines_are_deduplicated():
    """Confirmed against real dnsx v1.2.2 output: the same host can appear
    more than once in one run's JSONL, with byte-identical records. Without
    dedup, hostname/foreign counts silently double."""
    dup_record = {"host": "example.com", "a": ["93.184.216.34"], "ttl": 300}
    corr = correlate.Correlation(dns=[dup_record, dup_record, dup_record])
    ent = correlate.build_entities(corr, our_domains={"example.com"})
    assert len(ent.dns_records) == 1
    assert ent.ip_addresses[0]["hostname_count"] == 1


# ── Trap 2: CIDR membership must be backfilled onto ip_addresses ───────────

def test_ip_addresses_get_their_containing_cidr_backfilled():
    """cidr_blocks are only known once every block has been considered — an
    earlier version computed them in the same pass as ip_addresses and every
    `cidr` field came back None."""
    corr = correlate.Correlation(
        dns=[{"host": "example.com", "a": ["93.184.216.34"]}],
        cidrs_aggregated=["93.184.216.0/24"],
    )
    ent = correlate.build_entities(corr, our_domains={"example.com"})
    ip_entry = next(e for e in ent.ip_addresses if e["ip"] == "93.184.216.34")
    assert ip_entry["cidr"] == "93.184.216.0/24"


def test_narrowest_cidr_wins_when_blocks_nest():
    corr = correlate.Correlation(
        dns=[{"host": "example.com", "a": ["93.184.216.34"]}],
        cidrs_aggregated=["93.184.216.0/24", "93.184.216.32/28"],
    )
    ent = correlate.build_entities(corr, our_domains={"example.com"})
    ip_entry = next(e for e in ent.ip_addresses if e["ip"] == "93.184.216.34")
    assert ip_entry["cidr"] == "93.184.216.32/28"


# ── Trap 3: round-robin DNS breaks (host, ip, port) cert matching ──────────

def test_cert_attaches_by_host_and_port_despite_round_robin_ip_mismatch():
    """httpx and tlsx each resolve the hostname independently; with
    round-robin DNS they routinely land on DIFFERENT addresses for the same
    host:port (confirmed against a real scan of example.com). Matching
    strictly on (host, ip, port) silently drops every cert."""
    entities = correlate.Entities(
        certificates=[{
            "cert_sha256": "abc123", "subject_cn": "example.com",
            "cipher_grade": "secure", "san_count": 1,
        }],
        cert_names=[{"cert_sha256": "abc123", "name": "example.com"}],
        cert_observations=[{
            "cert_sha256": "abc123", "host": "example.com",
            "ip": "2606:4700:10::6814:179a", "port": 443,
        }],
    )
    # httpx's probe of the SAME host:port answered from a DIFFERENT address.
    rec = {"host": "example.com", "port": 443,
          "host_ip": "2606:4700:10::ac42:93f3", "serves_content": True}
    correlate.attach([rec], entities)
    assert rec["cert_subject_cn"] == "example.com"
    assert rec["cert_sha256"] == "abc123"


def test_exact_ip_match_preferred_when_multiple_observations_exist():
    """When there genuinely are different certs per address at the same
    host:port, the exact IP match must win over an arbitrary first pick."""
    entities = correlate.Entities(
        certificates=[
            {"cert_sha256": "aaa", "subject_cn": "a.example.com"},
            {"cert_sha256": "bbb", "subject_cn": "b.example.com"},
        ],
        cert_names=[],
        cert_observations=[
            {"cert_sha256": "aaa", "host": "example.com", "ip": "1.1.1.1", "port": 443},
            {"cert_sha256": "bbb", "host": "example.com", "ip": "2.2.2.2", "port": 443},
        ],
    )
    rec = {"host": "example.com", "port": 443, "host_ip": "2.2.2.2",
          "serves_content": True}
    correlate.attach([rec], entities)
    assert rec["cert_subject_cn"] == "b.example.com"


# ── Trap 4: tlsx omits misconfiguration booleans entirely when false ───────

def test_missing_misconfig_key_is_treated_as_false_not_unknown():
    """Confirmed against real tlsx v1.2.2 output (Go `omitempty`): `expired`/
    `self_signed`/`mismatched` are ABSENT from the JSON when false, not
    present as `false`. `.get(..., default)` with the wrong default would
    misread absence as a positive finding."""
    clean_cert = {
        "fingerprint_hash": {"sha256": "clean123"},
        "subject_cn": "example.com", "host": "example.com", "ip": "1.2.3.4",
        "port": 443,
        # No expired/self_signed/mismatched/revoked/untrusted keys at all.
    }
    corr = correlate.Correlation(tls=[clean_cert])
    ent = correlate.build_entities(corr, our_domains={"example.com"})
    cert = ent.certificates[0]
    assert cert["expired"] is False
    assert cert["self_signed"] is False
    assert cert["mismatched"] is False


# ── ours vs. foreign classification ─────────────────────────────────────────

def test_ptr_name_outside_our_domains_counts_as_foreign():
    corr = correlate.Correlation(
        ptr=[{"host": "8.8.8.8", "ptr": ["dns.google"]}],
    )
    ent = correlate.build_entities(corr, our_domains={"example.com"})
    ip_entry = next(e for e in ent.ip_addresses if e["ip"] == "8.8.8.8")
    assert ip_entry["hostname_count"] == 0
    assert ip_entry["foreign_name_count"] == 1
    assert ip_entry["foreign_domain_count"] == 1


def test_cert_san_covering_a_foreign_domain_is_flagged():
    corr = correlate.Correlation(tls=[{
        "fingerprint_hash": {"sha256": "shared123"},
        "subject_cn": "example.com",
        "subject_an": ["example.com", "unrelated-tenant.example"],
        "host": "example.com", "ip": "1.2.3.4", "port": 443,
    }])
    ent = correlate.build_entities(corr, our_domains={"example.com"})
    cert = ent.certificates[0]
    assert cert["foreign_domain_count"] == 1
    assert cert["in_scope_name_count"] == 1


# ── ip_sort_key: v4 and v6 both range-scan correctly ────────────────────────

def test_ip_sort_key_orders_numerically_within_a_family():
    ascending = ("9.255.255.255", "10.0.0.1", "10.0.0.255", "10.0.1.0")
    keys = [correlate.ip_sort_key(ip) for ip in ascending]
    assert keys == sorted(keys)


def test_ip_sort_key_is_fixed_width():
    v4 = correlate.ip_sort_key("1.2.3.4")
    v6 = correlate.ip_sort_key("2606:4700:10::6814:179a")
    assert len(v4) == len(v6) == 32
