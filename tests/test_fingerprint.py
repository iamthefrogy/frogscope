"""The passive detection catalogue: precision, honesty about gaps, and provenance."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

from frogscope.config import load_config
from frogscope.ingest import fingerprint

CONFIG = Path("config")


@pytest.fixture(scope="module")
def cfg():
    return load_config()


@pytest.fixture(scope="module")
def catalogue(cfg):
    return fingerprint.load_catalogue(cfg.config_dir)


def rec(**kw):
    base = {"port": 443, "title": "", "tech_names": [], "cpe_products": [],
            "webserver": "", "body_preview": "", "favicon_md5": ""}
    base.update(kw)
    return base


# ── Structure ───────────────────────────────────────────────────────────────

def test_the_catalogue_loads(catalogue):
    assert catalogue.total > 80
    assert catalogue.panels


def test_every_entry_can_actually_fire(catalogue):
    """An entry with no matcher never fires, and looks like coverage on a report."""
    for matcher in catalogue.all_matchers():
        assert (matcher.title or matcher.tech or matcher.cpe or matcher.body
                or matcher.favicon or matcher.server), matcher.id


def test_ids_are_unique(catalogue):
    ids = [m.id for m in catalogue.all_matchers()]
    assert len(ids) == len(set(ids))


def test_every_panel_group_has_a_severity(catalogue):
    """A group with no mapping means a match scores nothing — a silent no-op."""
    for matcher in catalogue.panels:
        assert matcher.group in fingerprint.GROUP_EXPOSURE, matcher.id


def test_every_regex_compiles():
    doc = yaml.safe_load((CONFIG / "fingerprints.yaml").read_text(encoding="utf-8"))
    for section in ("panels", "default_pages", "disclosure", "storage_exposure"):
        for entry in doc.get(section) or []:
            for key in ("title", "body", "server"):
                for pattern in entry.get(key) or []:
                    re.compile(str(pattern))


# ── Precision: the defect this catalogue was built around ───────────────────

def test_running_a_platform_is_not_an_exposed_admin_panel(cfg, catalogue):
    """The bug: `tech: [WordPress]` matched 66 ordinary marketing pages on a real
    estate and zero actual admin panels. Running WordPress says nothing about
    whether wp-admin is reachable."""
    marketing = rec(title="Commodities Trading and Risk Management Solutions",
                    tech_names=["WordPress", "PHP"])
    out = fingerprint.identify(marketing, catalogue)
    assert out["panel_product"] == "", (
        f"a marketing page was reported as {out['panel_product']!r}")


def test_the_actual_admin_page_is_still_detected(cfg, catalogue):
    login = rec(title="Log In &lsaquo; Acme Blog &#8212; WordPress",
                tech_names=["WordPress"])
    out = fingerprint.identify(login, catalogue)
    assert "WordPress" in out["panel_product"]


def test_require_title_blocks_technology_only_matches(catalogue):
    by_id = {m.id: m for m in catalogue.panels}
    guarded = by_id["PANEL_WORDPRESS_ADMIN"]
    assert guarded.require_title is True
    matched, _signal, _observed = guarded.evaluate(
        rec(tech_names=["WordPress"], title="Homepage"))
    assert matched is False


def test_products_whose_name_is_the_panel_do_not_need_a_title(catalogue):
    """Nobody runs Jenkins without the dashboard being the product, so a
    technology match there is legitimate evidence."""
    by_id = {m.id: m for m in catalogue.panels}
    assert by_id["PANEL_JENKINS"].require_title is False
    matched, signal, _ = by_id["PANEL_JENKINS"].evaluate(
        rec(tech_names=["Jenkins"]))
    assert matched and signal == "technology"


def test_a_port_constraint_narrows_rather_than_matches_alone(catalogue):
    """Without this, a port rule would flag every host answering on that port."""
    by_id = {m.id: m for m in catalogue.panels}
    weblogic = by_id["PANEL_WEBLOGIC"]
    assert weblogic.ports
    matched, _s, _o = weblogic.evaluate(rec(port=7001, title="Some other app"))
    assert matched is False
    matched, _s, _o = weblogic.evaluate(rec(port=7001, title="Oracle WebLogic"))
    assert matched is True
    # Right title, wrong port: the constraint must actually constrain.
    matched, _s, _o = weblogic.evaluate(rec(port=443, title="Oracle WebLogic"))
    assert matched is False


# ── Auditability ────────────────────────────────────────────────────────────

def test_a_match_reports_which_signal_fired_and_what_was_seen(catalogue):
    """A bare boolean cannot be argued with. "Jenkins because the title was X" can."""
    out = fingerprint.identify(rec(title="Dashboard [Jenkins]"), catalogue)
    hit = next(h for h in out["fingerprint_hits"] if h["id"] == "PANEL_JENKINS")
    assert hit["signal"] == "title"
    assert "Jenkins" in hit["observed"]


def test_severity_follows_authority_not_alphabet(catalogue):
    """A build system outranks a webmail even when both match confidently."""
    ci = fingerprint.identify(rec(title="Dashboard [Jenkins]"), catalogue)
    mail = fingerprint.identify(rec(title="Roundcube Webmail"), catalogue)
    ranks = {"critical": 4, "high": 3, "medium": 2, "low": 1, "": 0}
    assert ranks[ci["panel_exposure"]] > ranks[mail["panel_exposure"]]


def test_the_worst_product_drives_the_summary_field(catalogue):
    """Several products can legitimately match one endpoint. The summary must be
    the one that matters most, not the first one checked."""
    both = rec(title="Grafana", tech_names=["Jenkins"])
    out = fingerprint.identify(both, catalogue)
    assert out["panel_count"] >= 2
    assert out["panel_product"] == "Jenkins", "the build system should win"


def test_nothing_matches_an_empty_record(catalogue):
    out = fingerprint.identify(rec(), catalogue)
    assert out["fingerprint_count"] == 0
    assert out["panel_product"] == ""


# ── Honesty about what could not be checked ─────────────────────────────────

def test_a_check_needing_absent_data_is_skipped_not_passed(catalogue):
    """Silently passing a check the scan could not perform is how a dashboard
    reassures people about data it never had."""
    out = fingerprint.identify(rec(title="Anything"), catalogue)
    assert any("body_preview" in note for note in out["fingerprint_skipped"])


def test_coverage_separates_blocked_from_clean(catalogue):
    with_bodies = fingerprint.coverage(catalogue, {
        "title", "tech_names", "cpe_products", "webserver", "body_preview",
        "favicon_md5"})
    without = fingerprint.coverage(catalogue, {"title", "tech_names"})
    assert without["blocked"] > with_bodies["blocked"]
    assert without["blocked_by_field"]


def test_coverage_reports_partial_evaluability(catalogue):
    """A matcher with title+body can still fire on the title alone, but with less
    evidence than it was written to use. Collapsing that into "fine" overstates
    the result."""
    report = fingerprint.coverage(catalogue, {"title", "tech_names",
                                              "cpe_products", "webserver"})
    assert report["partial"] > 0
    assert report["evaluable"] + report["partial"] + report["blocked"] == \
        report["total"]


def test_body_only_entries_are_blocked_without_bodies(catalogue):
    report = fingerprint.coverage(catalogue, {"title", "tech_names"})
    assert "DISCLOSE_ENV_IN_BODY" in report["blocked_ids"]


# ── Takeover catalogue ──────────────────────────────────────────────────────

def test_the_takeover_catalogue_covers_the_upstream_provider_set():
    doc = yaml.safe_load((CONFIG / "takeover.yaml").read_text(encoding="utf-8"))
    providers = doc["providers"]
    assert len(providers) >= 80, (
        "upstream ships ~72 takeover templates plus the cloud providers we "
        "already had; a much smaller number means the review lapsed")


def test_every_takeover_provider_has_a_suffix_and_a_grade():
    doc = yaml.safe_load((CONFIG / "takeover.yaml").read_text(encoding="utf-8"))
    for entry in doc["providers"]:
        assert entry.get("cname_suffixes"), entry["provider"]
        assert entry.get("grade") in ("high", "medium", "low"), entry["provider"]


def test_high_grade_requires_a_provider_specific_fingerprint():
    """`high` claims the provider itself said the resource does not exist. A bare
    CNAME suffix cannot support that, and overclaiming is how a findings feed
    loses credibility."""
    doc = yaml.safe_load((CONFIG / "takeover.yaml").read_text(encoding="utf-8"))
    for entry in doc["providers"]:
        if entry.get("grade") == "high":
            assert entry.get("body_fingerprints") or entry.get("title_fingerprints"), \
                f"{entry['provider']} grades high with no fingerprint"


def test_takeover_provider_names_are_unique():
    doc = yaml.safe_load((CONFIG / "takeover.yaml").read_text(encoding="utf-8"))
    names = [e["provider"] for e in doc["providers"]]
    assert len(names) == len(set(names)), \
        [n for n in names if names.count(n) > 1]


# ── Provenance and the refresh path ─────────────────────────────────────────

def test_the_catalogue_records_where_it_came_from():
    """Without this, a review in six months starts from scratch."""
    doc = yaml.safe_load((CONFIG / "catalogue.yaml").read_text(encoding="utf-8"))
    assert doc["sources"]
    source = doc["sources"][0]
    assert source["last_reviewed"]
    assert source["adopted"]
    assert source["excluded"], \
        "what was deliberately skipped matters as much as what was taken"


def test_exclusions_carry_a_reason():
    """A bare exclusion list gets re-litigated every review."""
    doc = yaml.safe_load((CONFIG / "catalogue.yaml").read_text(encoding="utf-8"))
    for source in doc["sources"]:
        for entry in source.get("excluded") or []:
            assert entry.get("reason", "").strip(), entry.get("upstream")


def test_the_blocked_list_names_the_flag_that_unlocks_each_gap():
    doc = yaml.safe_load((CONFIG / "catalogue.yaml").read_text(encoding="utf-8"))
    for entry in doc["blocked_by_input"]:
        assert entry.get("fields")
        assert entry.get("unlocks_with")
        assert entry.get("covers")


def test_the_refresh_procedure_is_written_down():
    """The procedure lives in the README rather than a separate file, so there is
    one document to keep current instead of two that can disagree."""
    doc = Path("README.md")
    assert doc.exists()
    text = doc.read_text(encoding="utf-8")
    # The parts that make it repeatable rather than a vague intention.
    assert "require_title" in text, "the trap must be documented"
    assert "catalogue status" in text
    # A checklist, so a review is a sequence of steps rather than a vague intention.
    assert "### Checklist" in text
    assert "Refresh the detection catalogue" in text
    lower = text.lower()
    # The independence claim, which is the whole reason the procedure exists.
    assert "nothing depends on nuclei at runtime" in lower
    # The steps that make it repeatable rather than a vague intention.
    assert "establish the baseline" in lower
    assert "record the review" in lower
    # And the coverage limitation, stated rather than hidden.
    assert "single largest coverage gap" in lower


def test_no_runtime_dependency_on_nuclei():
    """The catalogue is inspiration and a checklist, never a runtime input."""
    for path in Path("frogscope").rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert "nuclei-templates" not in text or "docs/" in text, path
        assert "import nuclei" not in text
    manifest = Path("pyproject.toml").read_text(encoding="utf-8").lower()
    assert "nuclei" not in manifest


# ── Rules wiring ────────────────────────────────────────────────────────────

def test_the_new_rules_reference_fields_that_exist(cfg):
    from frogscope.scoring.rules import load_ruleset, validate_ruleset
    problems = validate_ruleset(load_ruleset(cfg.config_dir))
    assert problems == []


def test_panel_rules_exist_for_every_severity_bearing_group(cfg):
    """A group the catalogue can produce but no rule consumes is dead weight."""
    from frogscope.scoring.rules import load_ruleset

    ruleset = load_ruleset(cfg.config_dir)
    import json
    blob = json.dumps([r.when for r in ruleset.rules])
    for group in fingerprint.GROUP_EXPOSURE:
        assert group in blob, f"no rule consumes panel_group {group!r}"


# ── Pattern precision (regression) ──────────────────────────────────────────

def test_no_pattern_has_an_unescaped_space_padded_pipe():
    """`Welcome | PRTG` is a regex, so the pipe is alternation: it matched the bare
    word "Welcome" and reported a default nginx page as a PRTG install. Page titles
    use " | " as a literal separator, so it has to be escaped."""
    doc = yaml.safe_load((CONFIG / "fingerprints.yaml").read_text(encoding="utf-8"))
    offenders = []
    for section in ("panels", "default_pages", "disclosure", "storage_exposure"):
        for entry in doc.get(section) or []:
            for key in ("title", "body", "server"):
                for pattern in entry.get(key) or []:
                    text = str(pattern)
                    if "(" in text:          # deliberate grouped alternation
                        continue
                    if re.search(r"(?<!\\)\s\|\s|(?<!\\)\|\s|\s(?<!\\)\|", text):
                        offenders.append((entry["id"], pattern))
    assert offenders == []


def test_no_alternative_is_too_short_to_be_distinctive():
    """A two- or three-character alternative matches inside ordinary words. "BMC"
    appears in prose; "iLO" appears inside other words."""
    doc = yaml.safe_load((CONFIG / "fingerprints.yaml").read_text(encoding="utf-8"))
    offenders = []
    for section in ("panels", "default_pages", "disclosure", "storage_exposure"):
        for entry in doc.get(section) or []:
            for pattern in entry.get("title") or []:
                for alt in str(pattern).split("|"):
                    bare = alt.strip().strip("^$")
                    if 0 < len(bare) < 4 and bare.isalnum():
                        offenders.append((entry["id"], alt))
    assert offenders == [], "anchor these with \\b"


def test_a_default_nginx_page_is_not_reported_as_a_product(catalogue):
    """The exact false positive the escaping bug produced."""
    out = fingerprint.identify(rec(title="Welcome to nginx!",
                                   webserver="nginx/1.18.0"), catalogue)
    assert out["panel_product"] == "", out["panel_product"]
    # It should still be recognised as an unfinished deployment.
    assert out["is_default_page"] is True


def test_the_validator_rejects_the_pattern_bugs_it_was_written_for(tmp_path):
    """The check has to fail on a bad catalogue, or it is decoration."""
    import shutil
    import subprocess

    shutil.copytree(CONFIG, tmp_path / "config")
    path = tmp_path / "config" / "fingerprints.yaml"
    path.write_text(path.read_text(encoding="utf-8")
                    .replace(r"'Welcome \| PRTG'", "'Welcome | PRTG'"),
                    encoding="utf-8")

    result = subprocess.run(
        ["python3", "-m", "frogscope", "--config", str(tmp_path / "config"),
         "catalogue", "validate"],
        capture_output=True, text=True)
    assert result.returncode != 0
    assert "space-padded" in result.stdout
