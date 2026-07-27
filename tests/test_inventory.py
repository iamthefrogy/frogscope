"""Inventory, export, redaction, and gating tests."""

from __future__ import annotations

import json
import re
import zipfile
from pathlib import Path

import pytest

from frogscope.analytics import inventory as inv
from frogscope.config import load_config
from frogscope.db.connection import connect
from frogscope.db.migrate import migrate
from frogscope.export.redact import Redactor
from frogscope.export.xlsx import write_workbook
from frogscope.ingest import pipeline
from frogscope.scoring.rules import load_ruleset

FIXTURE = Path(__file__).parent / "fixtures" / "sample.csv"


@pytest.fixture(scope="module")
def cfg():
    return load_config()


@pytest.fixture(scope="module")
def ruleset(cfg):
    return load_ruleset(cfg.config_dir)


@pytest.fixture()
def db(tmp_path, cfg, monkeypatch):
    monkeypatch.setattr(cfg, "data_dir", tmp_path)
    conn = connect(tmp_path / "inv.sqlite")
    migrate(conn)
    result = pipeline.ingest(conn, cfg, FIXTURE, project="inv", label="r1",
                             allow_incomplete=True, keep_raw=False)
    run = conn.execute("SELECT * FROM runs WHERE id = ?",
                       (result.run_id,)).fetchone()
    yield conn, run, result
    conn.close()


# ── Everything counts hosts, not endpoints ──────────────────────────────────

def test_technology_counts_hosts_not_endpoints(db, ruleset):
    """A Cloudflare-fronted host contributes a dozen near-identical endpoints, so
    endpoint counts overstate every inventory total several-fold."""
    conn, run, _result = db
    data = inv.technology(conn, run["id"], ruleset.lifecycle)
    total_hosts = conn.execute(
        "SELECT COUNT(DISTINCT host) n FROM endpoints WHERE run_id = ?",
        (run["id"],)).fetchone()["n"]
    for entry in data["tech"]:
        assert entry["hosts"] <= total_hosts, entry["name"]


def test_technology_host_counts_reconcile_with_sql(db, ruleset):
    conn, run, _result = db
    data = inv.technology(conn, run["id"], ruleset.lifecycle)
    if not data["tech"]:
        pytest.skip("fixture detected no technologies")
    top = data["tech"][0]
    actual = conn.execute(
        """SELECT COUNT(DISTINCT host) n FROM endpoints,
                  json_each(endpoints.lists_json, '$.tech')
            WHERE run_id = ? AND json_each.value = ?""",
        (run["id"], top["name"])).fetchone()["n"]
    # tech_names strips a trailing ":version", so a versioned entry will not match
    # the raw tech array exactly. Only assert when the name is unversioned.
    if not top["versions"]:
        assert top["hosts"] == actual


def test_version_spread_is_surfaced(db, ruleset):
    """One product at several versions is a patching-consistency problem that a
    single "outdated" flag hides."""
    conn, run, _result = db
    data = inv.technology(conn, run["id"], ruleset.lifecycle)
    for entry in data["inconsistent_versions"]:
        assert entry["version_count"] > 1
        assert len(entry["by_version"]) == entry["version_count"]


def test_eol_products_are_deduplicated_per_host(db, ruleset):
    conn, run, _result = db
    data = inv.technology(conn, run["id"], ruleset.lifecycle)
    actual = conn.execute(
        "SELECT COUNT(DISTINCT host) n FROM endpoints "
        "WHERE run_id = ? AND eol_count > 0", (run["id"],)).fetchone()["n"]
    assert data["totals"]["eol_hosts"] == actual


# ── Infrastructure ──────────────────────────────────────────────────────────

def test_real_port_count_is_never_negative(db):
    """A Cloudflare HTTPS alias port probed over cleartext is BOTH an alias and an
    artefact, so subtracting each total double-subtracts and goes negative."""
    conn, run, _result = db
    data = inv.infrastructure(conn, run["id"])
    for entry in data["port_rows"]:
        assert entry["real"] >= 0, f"port {entry['port']} reported {entry['real']}"
        assert entry["real"] <= entry["total"]


def test_real_port_count_matches_direct_sql(db):
    conn, run, _result = db
    data = inv.infrastructure(conn, run["id"])
    for entry in data["port_rows"]:
        actual = conn.execute(
            "SELECT COUNT(*) n FROM endpoints WHERE run_id = ? AND port = ? "
            "AND cf_alias_port = 0 AND scan_artifact = 0",
            (run["id"], entry["port"])).fetchone()["n"]
        assert entry["real"] == actual, entry["port"]


def test_addresses_include_every_record_not_just_the_answering_one(db):
    """Blast radius is built from the whole A-record set, so it does not shift
    when round-robin DNS answers with a different address."""
    conn, run, _result = db
    data = inv.infrastructure(conn, run["id"])
    listed = {a["ip"] for a in data["addresses"]}
    sample = conn.execute(
        "SELECT lists_json FROM endpoints WHERE run_id = ? "
        "AND lists_json LIKE '%\"a\":[\"%' LIMIT 1", (run["id"],)).fetchone()
    if sample is None:
        pytest.skip("fixture has no A records")
    records = (json.loads(sample["lists_json"]) or {}).get("a") or []
    if len(records) > 1:
        assert set(records) <= listed


def test_port_grid_covers_every_host(db):
    conn, run, _result = db
    data = inv.infrastructure(conn, run["id"])
    hosts = conn.execute(
        "SELECT COUNT(DISTINCT host) n FROM endpoints WHERE run_id = ?",
        (run["id"],)).fetchone()["n"]
    assert data["grid_total"] == hosts


def test_port_grid_is_ordered_by_real_surface(db):
    conn, run, _result = db
    data = inv.infrastructure(conn, run["id"])
    counts = [row["real_ports"] for row in data["grid"]]
    assert counts == sorted(counts, reverse=True)


# ── Auth surfaces ───────────────────────────────────────────────────────────

def test_federated_and_local_auth_are_counted_separately(db):
    """Federation is a good property. The risk is a surface handling credentials
    itself, so collapsing the two would hide the distinction that matters."""
    conn, run, _result = db
    data = inv.auth_surfaces(conn, run["id"])
    for group in data["groups"]:
        assert group["federated"] + group["local"] == group["endpoint_count"]


def test_auth_groups_reconcile_with_sql(db):
    conn, run, _result = db
    data = inv.auth_surfaces(conn, run["id"])
    for group in data["groups"]:
        actual = conn.execute(
            "SELECT COUNT(DISTINCT host) n FROM endpoints WHERE run_id = ? "
            "AND scan_artifact = 0 AND auth_surface_type = ?",
            (run["id"], group["type"])).fetchone()["n"]
        assert group["hosts"] == actual, group["type"]


def test_scan_artefacts_are_excluded_from_auth_inventory(db):
    conn, run, _result = db
    data = inv.auth_surfaces(conn, run["id"])
    keys = {e["endpoint_key"] for g in data["groups"] for e in g["endpoints"]}
    artefacts = {
        r["endpoint_key"] for r in conn.execute(
            "SELECT endpoint_key FROM endpoints WHERE run_id = ? "
            "AND scan_artifact = 1", (run["id"],))
    }
    assert not (keys & artefacts)


def test_remote_access_is_deduplicated_per_host(db):
    conn, run, _result = db
    data = inv.auth_surfaces(conn, run["id"])
    hosts = [r["host"] for r in data["remote_access"]]
    assert len(hosts) == len(set(hosts))


# ── Takeover ────────────────────────────────────────────────────────────────

def test_takeover_never_claims_confirmed(db, ruleset):
    """Confirming a takeover needs a live DNS and provider check, and ingest makes
    no network requests."""
    conn, run, _result = db
    data = inv.takeover(conn, run["id"], ruleset.takeover)
    for candidate in data["candidates"]:
        assert candidate["confidence"] != "confirmed"


def test_takeover_candidates_carry_evidence_and_a_way_to_check(db, ruleset):
    conn, run, _result = db
    data = inv.takeover(conn, run["id"], ruleset.takeover)
    if not data["candidates"]:
        pytest.skip("fixture has no takeover candidates")
    for candidate in data["candidates"]:
        assert candidate["verify_commands"]
        assert any("dig" in c for c in candidate["verify_commands"])


def test_broken_origins_are_kept_apart_from_takeover_candidates(db, ruleset):
    """A 525 means the origin answers and its TLS is broken — an availability bug,
    not a dangling record. Merging them is how a takeover feed loses credibility."""
    conn, run, _result = db
    data = inv.takeover(conn, run["id"], ruleset.takeover)
    candidate_hosts = {c["host"] for c in data["candidates"]}
    broken_hosts = {b["host"] for b in data["broken_origins"]}
    assert not (candidate_hosts & broken_hosts)
    for entry in data["broken_origins"]:
        assert entry["origin_health"] in ("tls_broken", "unreachable", "dns_missing")


def test_takeover_grades_are_ordered_worst_first(db, ruleset):
    conn, run, _result = db
    data = inv.takeover(conn, run["id"], ruleset.takeover)
    order = {"high": 0, "medium": 1, "low": 2}
    ranks = [order.get(c["grade"], 3) for c in data["candidates"]]
    assert ranks == sorted(ranks)


# ── Redaction ───────────────────────────────────────────────────────────────

def test_redaction_removes_the_real_domain_everywhere():
    """An allow-list of fields is the wrong shape: `zone`, `registrable_domain`,
    and `tech_flat` all carry the domain, and any field missed leaks silently."""
    redactor = Redactor(salt="fixed")
    row = redactor.row({
        "host": "adm.iem.acme-corp.com",
        "host_display": "ADM.iem.Acme-Corp.com",
        "endpoint_key": "adm.iem.acme-corp.com:443",
        "zone": "iem.acme-corp.com",
        "registrable_domain": "acme-corp.com",
        "host_ip": "203.0.113.9",
        "final_url": "https://adm.iem.acme-corp.com/login?x=1",
        "title": "Login for adm.iem.acme-corp.com",
        "port": 443,
    })
    blob = json.dumps(row).lower()
    assert "acme-corp" not in blob
    assert "203.0.113.9" not in blob
    assert row["port"] == 443, "non-identifying values must pass through"


def test_redaction_preserves_zone_structure():
    """Two hosts in one zone must still look related, or the findings stop making
    sense to the reader."""
    redactor = Redactor(salt="fixed")
    a = redactor.host("adm.iem.acme.com")
    b = redactor.host("met.iem.acme.com")
    c = redactor.host("www.acme.com")
    assert a != b
    assert a.split(".")[1:] == b.split(".")[1:], "same zone shares a suffix"
    assert a.split(".")[-2:] == c.split(".")[-2:], "same domain shares a root"
    assert len(a.split(".")) == len(["adm", "iem", "acme", "com"])


def test_redaction_is_stable_within_one_export():
    redactor = Redactor(salt="fixed")
    assert redactor.host("a.b.example.com") == redactor.host("A.B.EXAMPLE.COM")


def test_two_exports_cannot_be_cross_referenced():
    """Salted per export, so two redacted documents cannot be joined to recover
    the real names."""
    assert (Redactor().host("a.example.com")
            != Redactor().host("a.example.com"))


def test_redaction_uses_reserved_documentation_ranges():
    redactor = Redactor(salt="fixed")
    assert redactor.ip("8.8.8.8").startswith("198.51.100.")
    assert redactor.ip("2606:4700::1").startswith("2001:db8::")


# ── XLSX ────────────────────────────────────────────────────────────────────

def test_workbook_is_a_valid_zip_of_parseable_xml(tmp_path):
    import xml.dom.minidom as minidom

    path = tmp_path / "wb.xlsx"
    write_workbook(path, [
        ("Sheet one", ["a", "b"], [{"a": 1, "b": "x"}, {"a": 2, "b": None}]),
        ("Sheet two", ["z"], [{"z": True}]),
    ])
    with zipfile.ZipFile(path) as zf:
        assert zf.testzip() is None
        for name in zf.namelist():
            minidom.parseString(zf.read(name))


def test_workbook_escapes_xml_and_strips_control_characters(tmp_path):
    """One stray control character makes the whole workbook unopenable, not just
    one bad cell."""
    path = tmp_path / "esc.xlsx"
    write_workbook(path, [("S", ["v"], [{"v": "a<b>&c\x01d"}])])
    with zipfile.ZipFile(path) as zf:
        sheet = zf.read("xl/worksheets/sheet1.xml").decode()
    assert "&lt;b&gt;" in sheet
    assert "&amp;c" in sheet
    assert "\x01" not in sheet


def test_workbook_renames_duplicate_sheets(tmp_path):
    path = tmp_path / "dup.xlsx"
    write_workbook(path, [("Same", ["a"], []), ("Same", ["a"], [])])
    with zipfile.ZipFile(path) as zf:
        names = re.findall(r'name="([^"]+)"',
                           zf.read("xl/workbook.xml").decode())
    assert len(set(names)) == len(names)


def test_workbook_handles_no_sheets(tmp_path):
    path = tmp_path / "empty.xlsx"
    write_workbook(path, [])
    with zipfile.ZipFile(path) as zf:
        assert zf.testzip() is None


def test_workbook_sheet_name_is_truncated_and_sanitised(tmp_path):
    path = tmp_path / "long.xlsx"
    write_workbook(path, [("a" * 60 + "[bad]/name", ["x"], [])])
    with zipfile.ZipFile(path) as zf:
        names = re.findall(r'name="([^"]+)"',
                           zf.read("xl/workbook.xml").decode())
    assert len(names[0]) <= 31
    assert not set("[]:*?/\\") & set(names[0])


# ── Ownership ───────────────────────────────────────────────────────────────

def test_ownership_starts_unconfigured_and_says_so(cfg):
    """Ownership is not observable from a scan. Guessing it would be worse than
    leaving the cut collapsed to zone, so the UI is told to say that."""
    assert cfg.has_ownership is False
    assert cfg.ownership_note
    assert "ownership.yaml" in cfg.ownership_note


def test_ownership_rules_are_applied_in_order(cfg, tmp_path):
    import shutil

    import yaml

    staging = tmp_path / "config"
    shutil.copytree(cfg.config_dir, staging)
    (staging / "ownership.yaml").write_text(yaml.safe_dump({
        "rules": [
            {"match": r"^adm\.", "owner": "Platform", "business_unit": "Tech",
             "criticality": "tier1"},
            {"match": ".*", "owner": "Unassigned", "business_unit": "Unknown",
             "criticality": "tier3"},
        ],
        "tiers": {},
        "unconfigured_note": "n/a",
    }))
    patched = load_config(staging, tmp_path)
    assert patched.has_ownership
    assert patched.owner_for("adm.iem.example.com")["owner"] == "Platform"
    assert patched.owner_for("other.example.com")["owner"] == "Unassigned"


def test_ownership_is_stamped_onto_records(db):
    conn, run, _result = db
    columns = {r["name"] for r in conn.execute("PRAGMA table_info(endpoints)")}
    assert {"owner", "business_unit", "criticality"} <= columns
    host_columns = {r["name"] for r in conn.execute("PRAGMA table_info(host_rollup)")}
    assert {"owner", "business_unit", "criticality"} <= host_columns


# ── Gating ──────────────────────────────────────────────────────────────────

def test_gate_clause_states_the_failure_condition(db):
    from frogscope.cli import evaluate_gate

    conn, run, _result = db
    breached, messages = evaluate_gate(conn, run, "findings>-1")
    assert breached is True, "findings > -1 is always true, so it must breach"
    assert any("BREACH" in m for m in messages)

    breached, messages = evaluate_gate(conn, run, "findings>1000000")
    assert breached is False
    assert all("ok" in m for m in messages)


def test_gate_rejects_unparseable_clauses(db):
    from frogscope.cli import evaluate_gate

    conn, run, _result = db
    with pytest.raises(ValueError):
        evaluate_gate(conn, run, "not a clause")


def test_gate_reports_an_unknown_metric_rather_than_passing_silently(db):
    """Failing open on a typo would make a CI gate worthless."""
    from frogscope.cli import evaluate_gate

    conn, run, _result = db
    breached, messages = evaluate_gate(conn, run, "criticl>0")
    assert breached is True
    assert any("unknown metric" in m for m in messages)


def test_gate_with_no_clauses_does_not_breach(db):
    from frogscope.cli import evaluate_gate

    conn, run, _result = db
    assert evaluate_gate(conn, run, "") == (False, [])


# ── Saved views ─────────────────────────────────────────────────────────────

def test_saved_view_rejects_an_unknown_column(db, cfg):
    """A saved view is replayed into the query layer, so column names have to be
    validated when stored rather than trusted on read."""
    from frogscope.query.catalog import Catalog

    catalog = Catalog(cfg)
    assert "host" in catalog
    assert "host; DROP TABLE endpoints" not in catalog
