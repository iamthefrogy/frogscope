"""Executive KPI and narrative tests.

The central property under test: the executive page must not be able to report a
reassuring headline while the underlying data says otherwise. That failure mode
is silent and expensive, so it gets explicit tests rather than a visual check.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from frogscope.analytics import kpis, narrative
from frogscope.config import load_config
from frogscope.db.connection import connect
from frogscope.db.migrate import migrate
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
def built(tmp_path, cfg, ruleset, monkeypatch):
    monkeypatch.setattr(cfg, "data_dir", tmp_path)
    conn = connect(tmp_path / "exec.sqlite")
    migrate(conn)
    pipeline.ingest(conn, cfg, FIXTURE, project="exec", label="fixture",
                    allow_incomplete=True, keep_raw=False)
    run = conn.execute("SELECT * FROM runs ORDER BY id DESC LIMIT 1").fetchone()
    data = kpis.build(conn, run, ruleset)
    data["narrative"] = narrative.build(data)
    yield data, conn
    conn.close()


# ── Host posture is the headline ────────────────────────────────────────────

def test_posture_is_host_weighted_not_endpoint_weighted(built):
    """A host is the unit of remediation. An endpoint-weighted average lets a
    Cloudflare-fronted host's dozen near-identical endpoints dilute the picture."""
    data, _conn = built
    assert data["posture"]["index_basis"] == "host"
    assert "host" in data["posture"]["formula"].lower()


def test_host_counts_reconcile(built):
    data, conn = built
    posture = data["posture"]
    actual = conn.execute("SELECT COUNT(*) n FROM host_rollup").fetchone()["n"]
    assert posture["total_hosts"] == actual
    assert (sum(posture["by_worst_finding"].values()) + posture["clean"]
            == posture["total_hosts"])


def test_needs_attention_counts_only_critical_and_high(built):
    data, conn = built
    hosts = {
        r["asset_key"] for r in conn.execute(
            "SELECT DISTINCT asset_key FROM findings "
            "WHERE status != 'resolved' AND severity IN ('critical','high')")
    }
    assert data["posture"]["needs_attention"] == len(hosts)


def test_headline_states_the_host_count_not_an_index(built):
    """An index-led headline invites the wrong conclusion when most endpoints are
    clean but most hosts are not."""
    data, _conn = built
    headline = data["narrative"]["headline"]
    posture = data["posture"]
    if posture["needs_attention"]:
        assert str(posture["needs_attention"]) in headline
        assert str(posture["total_hosts"]) in headline


def test_a_clean_estate_reads_as_clean(cfg, ruleset):
    """The inverse case: no findings must not produce alarming language."""
    empty = {
        "posture": {"total_hosts": 10, "needs_attention": 0, "clean": 10,
                    "by_worst_finding": {}, "needs_attention_pct": 0.0,
                    "index": 100},
        "surface": {"endpoints": 10, "real_endpoints": 10, "hosts": 10,
                    "scan_artifacts": 0, "cf_alias_ports": 0},
        "protection": {"segments": [], "total": 0, "unprotected": 0},
        "themes": [], "by_zone": [], "by_env": [], "eol": {"products": [],
                                                           "host_count": 0},
    }
    story = narrative.build(empty)
    assert "None of the 10 hosts" in story["headline"]
    assert not story["themes"]


# ── Narrative integrity ─────────────────────────────────────────────────────

def test_every_narrative_claim_traces_to_a_number_on_the_page(built):
    """Each theme sentence must name a host count that matches the findings
    table, so a reader can always check the claim."""
    data, conn = built
    for theme in data["narrative"]["themes"]:
        actual = conn.execute(
            "SELECT COUNT(DISTINCT asset_key) n FROM findings "
            "WHERE rule_id = ? AND status != 'resolved'",
            (theme["rule_id"],)).fetchone()["n"]
        assert theme["hosts"] == actual
        assert str(actual) in theme["sentence"]


def test_narrative_is_deterministic(built, ruleset):
    """Templates, not generation: identical data must give identical prose."""
    data, conn = built
    run = conn.execute("SELECT * FROM runs ORDER BY id DESC LIMIT 1").fetchone()
    again = narrative.build(kpis.build(conn, run, ruleset))
    assert again == data["narrative"]


def test_scale_note_explains_the_probe_to_service_gap(built):
    data, _conn = built
    note = narrative.scale_note(data)
    surface = data["surface"]
    if surface["real_endpoints"] != surface["endpoints"]:
        assert str(surface["real_endpoints"]) in note
        assert str(surface["endpoints"]) in note
        assert "alias" in note.lower() or "artefact" in note.lower()


def test_possible_confidence_is_flagged_in_prose(built):
    """A fingerprint-derived theme must say so, not read as confirmed."""
    data, _conn = built
    for theme in data["narrative"]["themes"]:
        if theme["rule_id"] == "SUSPECTED_VULN_FAMILY":
            assert theme["confidence_note"]
            assert "check" in theme["confidence_note"].lower()


def test_weak_environment_classification_is_disclosed(cfg):
    """When most hosts have no inferable environment, the per-environment cut is
    close to meaningless and must say so rather than being quietly shown."""
    data = {
        "posture": {"total_hosts": 100, "needs_attention": 10, "clean": 50,
                    "by_worst_finding": {"high": 10}, "needs_attention_pct": 10.0,
                    "index": 80},
        "by_env": [{"dimension": "unclassified", "hosts": 90,
                    "needs_attention": 5, "by_severity": {}, "max_score": 0}],
    }
    note = narrative.unclassified_note(data)
    assert "90%" in note
    assert "classify.yaml" in note


def test_strong_environment_classification_is_not_nagged_about(cfg):
    data = {
        "posture": {"total_hosts": 100, "needs_attention": 10, "clean": 50,
                    "by_worst_finding": {}, "needs_attention_pct": 10.0,
                    "index": 80},
        "by_env": [{"dimension": "unclassified", "hosts": 5,
                    "needs_attention": 0, "by_severity": {}, "max_score": 0}],
    }
    assert narrative.unclassified_note(data) == ""


# ── Protection composition ──────────────────────────────────────────────────

def test_protection_excludes_alias_ports(built):
    """An alias port serves the same origin site as :443, so counting it again
    would overstate coverage for whichever category it falls into."""
    data, conn = built
    real = conn.execute(
        "SELECT COUNT(*) n FROM endpoints "
        "WHERE scan_artifact = 0 AND cf_alias_port = 0").fetchone()["n"]
    assert data["protection"]["total"] == real


def test_protection_shares_sum_to_one_hundred(built):
    data, _conn = built
    shares = sum(s["pct"] for s in data["protection"]["segments"] if s["count"])
    assert 99.0 <= shares <= 101.0


def test_platform_only_is_not_counted_as_waf_protected(built):
    """WP Engine and Entra App Proxy are intermediaries but not WAFs. Reporting
    them as protected would overstate coverage."""
    data, conn = built
    segments = {s["key"]: s for s in data["protection"]["segments"]}
    waf_in_db = conn.execute(
        "SELECT COUNT(*) n FROM endpoints WHERE scan_artifact = 0 "
        "AND cf_alias_port = 0 AND waf_protected = 1").fetchone()["n"]
    assert segments["waf"]["count"] == waf_in_db


# ── Caveats ─────────────────────────────────────────────────────────────────

def test_caveats_always_state_the_probe_limitation(built):
    data, _conn = built
    joined = " ".join(data["caveats"]).lower()
    assert "unauthenticated" in joined
    assert "exploitable" in joined


def test_skipped_rules_appear_as_a_caveat(built):
    """A rule that could not run must never read as a rule that passed."""
    data, _conn = built
    joined = " ".join(data["caveats"])
    assert "could not be evaluated" in joined
    assert "not treated as passing" in joined


def test_single_run_reports_no_comparison_rather_than_zero_change(built):
    """A flat line reads as "no change"; the truth is "no data"."""
    data, _conn = built
    assert data["comparison"]["available"] is False
    assert "two" in data["comparison"]["reason"].lower()


# ── Dimensions and themes ───────────────────────────────────────────────────

def test_themes_are_ordered_worst_and_most_widespread_first(built):
    data, _conn = built
    order = ["critical", "high", "medium", "low", "info"]
    keys = [(order.index(t["severity"]), -t["hosts"]) for t in data["themes"]]
    assert keys == sorted(keys)


def test_themes_carry_remediation(built):
    data, _conn = built
    for theme in data["themes"]:
        assert theme["exec_line"], f"{theme['rule_id']} has no executive wording"


def test_by_dimension_rejects_an_arbitrary_column(built):
    """The dimension reaches SQL, so it must be whitelisted."""
    data, conn = built
    run = conn.execute("SELECT * FROM runs ORDER BY id DESC LIMIT 1").fetchone()
    with pytest.raises(ValueError):
        kpis.by_dimension(conn, run["id"], run["project_id"],
                          "host; DROP TABLE endpoints")


def test_top_hosts_name_their_worst_finding(built):
    data, _conn = built
    for host in data["top_hosts"]:
        if host["finding_count"]:
            assert host["worst_finding"] is not None
            assert host["worst_severity"]


def test_top_hosts_are_ordered_by_score(built):
    data, _conn = built
    scores = [h["risk_score"] or 0 for h in data["top_hosts"]]
    assert scores == sorted(scores, reverse=True)


# ── EOL summary ─────────────────────────────────────────────────────────────

def test_eol_products_are_deduplicated_per_host(built):
    """A host with the same EOL product on eight alias ports counts once."""
    data, conn = built
    for product in data["eol"]["products"]:
        assert product["hosts"] <= data["posture"]["total_hosts"]
    total_eol_hosts = conn.execute(
        "SELECT COUNT(DISTINCT host) n FROM endpoints WHERE eol_count > 0"
    ).fetchone()["n"]
    assert data["eol"]["host_count"] == total_eol_hosts


def test_eol_note_names_the_oldest_product(built):
    data, _conn = built
    if data["eol"]["products"]:
        note = narrative.eol_note(data)
        assert data["eol"]["products"][0]["name"] in note
