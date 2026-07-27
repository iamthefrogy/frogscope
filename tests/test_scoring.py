"""Scoring engine tests.

Three of these are regression tests for defects in the code this engine was
adapted from. Each defect is silent: the scorer keeps producing numbers, they
just stop meaning anything.
"""

from __future__ import annotations

from datetime import date

import pytest

from frogscope.config import load_config
from frogscope.scoring import predicate
from frogscope.scoring.engine import (
    residual_risk_index,
    score_host,
    score_record,
)
from frogscope.scoring.lifecycle import (
    derive_lifecycle,
    derive_scoring_inputs,
    derive_takeover,
    version_lt,
)
from frogscope.scoring.rules import (
    Rule,
    RuleSet,
    load_ruleset,
    rules_fingerprint,
    validate_ruleset,
)


@pytest.fixture(scope="module")
def cfg():
    return load_config()


@pytest.fixture(scope="module")
def ruleset(cfg):
    return load_ruleset(cfg.config_dir)


def base(**kw) -> dict:
    record = {
        "host": "x.example.com", "port": 443, "scheme": "https",
        "status_code": 200, "title": "", "response_class": "live_content",
        "serves_content": True, "scan_artifact": False, "cf_alias_port": False,
        "waf_blocked": False, "env": "prod", "port_category": "web_standard",
        "nonstd_port": False, "cdn_name": "", "cdn_type": "", "cdn": False,
        "hosting_provider": "", "hosting_kind": "", "edge_provider": "",
        "edge_kind": "", "origin_exposed": False, "no_waf": False,
        "waf_protected": False, "behind_proxy": False, "unprotected": False,
        "origin_health": "ok", "cf_error_code": None, "cname": [],
        "tech": [], "cpe_products": [], "tech_versions": {}, "wp_plugins": [],
        "webserver": "", "version_disclosure": False, "hsts_present": False,
        "auth_surface_type": "none", "federated_auth": False,
        "remote_access_exposed": False, "mgmt_surface": False,
        "no_tls_redirect": False, "is_nonprod_exposed": False,
        "ip_cluster_size": 1, "shared_infra": False, "concentration_risk": False,
        "content_cluster_size": 1, "api_surface": False,
        "sensitive_keyword_severity": "", "cdn_bypass_candidate": False,
        "server_header_inconsistent": False, "third_party_dependency": "",
        "azure_app_proxy": False, "defence_layers": 1, "title_class": "other",
        "host_ip": "203.0.113.1", "final_url": "",
    }
    record.update(kw)
    return record


def scored(ruleset, **kw):
    record = base(**kw)
    derive_scoring_inputs(record, ruleset.lifecycle, ruleset.takeover)
    return record, score_record(record, ruleset)


# ── The inherited defects ───────────────────────────────────────────────────

def test_absent_data_scores_nothing(ruleset):
    """The defect that mattered most.

    frogy_web's compute_priority awards +6 for "TLS version unknown", +4 for
    "Certificate validity unknown", +6 DMARC, +4 SPF, +3 DKIM, +2 DNSSEC — 25
    points against a hygiene cap of exactly 25, purely for data being absent.
    Fed an httpx CSV, every endpoint would max out its hygiene bucket on data
    never collected, and the ranking would be pure noise.
    """
    # hsts_present=True so nothing legitimately observable fires. Note the
    # distinction the engine has to keep: "HSTS was absent from the tech list we
    # did collect" is a real finding, whereas "we never collected TLS data at
    # all" must score nothing.
    _record, result = scored(ruleset, hsts_present=True)
    assert result.buckets.get("hygiene", 0) == 0, (
        "an endpoint with no observed hygiene problems must score zero hygiene, "
        "not points for missing TLS or DNS data"
    )
    skipped_ids = {s["rule_id"] for s in result.skipped}
    assert {"CERT_EXPIRED", "CERT_EXPIRING_SOON", "TLS_LEGACY_VERSION"} <= skipped_ids
    assert all(c.rule_id not in skipped_ids for c in result.contributions)


def test_observed_absence_still_scores(ruleset):
    """The other half of the distinction: HSTS missing from a tech list we DID
    collect is a genuine finding, and must not be swept up by the skip logic."""
    _record, result = scored(ruleset, hsts_present=False, scheme="https")
    assert any(c.rule_id == "HSTS_MISSING" for c in result.contributions)


def test_skipped_rules_are_reported_not_hidden(ruleset):
    _record, result = scored(ruleset)
    assert result.skipped, "rules with missing inputs must be reported"
    for entry in result.skipped:
        assert entry["missing_fields"]
        assert "did not collect" in entry["reason"]


def test_capping_is_independent_of_rule_order(cfg, ruleset):
    """frogy_web caps in source order, so which signals get truncated depends on
    where they happen to sit in the YAML. Shuffle and the score must not move."""
    import random

    record = base(origin_exposed=True, no_waf=True, unprotected=True,
                  cdn_bypass_candidate=True, mgmt_surface=True,
                  remote_access_exposed=True, version_disclosure=True,
                  webserver="Microsoft-IIS/10.0", shared_infra=True,
                  ip_cluster_size=60, concentration_risk=True)
    derive_scoring_inputs(record, ruleset.lifecycle, ruleset.takeover)
    baseline = score_record(record, ruleset)

    for seed in (1, 7, 42):
        shuffled = list(ruleset.rules)
        random.Random(seed).shuffle(shuffled)
        variant = RuleSet(
            version=ruleset.version, max_score=ruleset.max_score,
            bands=ruleset.bands, buckets=ruleset.buckets,
            severity_floor=ruleset.severity_floor,
            overlap_factor=ruleset.overlap_factor,
            rules=shuffled, modifiers=ruleset.modifiers,
            exclusions=ruleset.exclusions, lifecycle=ruleset.lifecycle,
            takeover=ruleset.takeover, modifier_floor=ruleset.modifier_floor,
        )
        result = score_record(record, variant)
        assert result.score == baseline.score
        assert result.buckets == baseline.buckets


def test_every_contribution_is_kept(ruleset):
    """frogy_web truncates reasons to the top five, so "why 72?" cannot be
    answered exactly. The drawer needs the whole trace."""
    _record, result = scored(
        ruleset, origin_exposed=True, no_waf=True, unprotected=True,
        mgmt_surface=True, remote_access_exposed=True, version_disclosure=True,
        webserver="nginx/1.10.0", shared_infra=True, ip_cluster_size=60,
        concentration_risk=True, api_surface=True,
        sensitive_keyword_severity="high", sensitive_keyword="payments")
    assert len(result.contributions) > 5
    assert sum(c.points_applied for c in result.contributions) == result.raw_score


def test_contributions_carry_observed_evidence(ruleset):
    _record, result = scored(ruleset, version_disclosure=True,
                             webserver="Microsoft-IIS/10.0")
    entry = next(c for c in result.contributions if c.rule_id == "VERSION_DISCLOSURE")
    assert entry.evidence.get("version_disclosure") is True
    assert "Microsoft-IIS/10.0" in entry.why


# ── Bucket caps and family de-duplication ───────────────────────────────────

def test_bucket_caps_are_respected(ruleset):
    _record, result = scored(
        ruleset, origin_exposed=True, no_waf=True, unprotected=True,
        cdn_bypass_candidate=True, mgmt_surface=True, remote_access_exposed=True,
        nonstd_port=True, is_nonprod_exposed=True, env="dev")
    for bucket, total in result.buckets.items():
        assert total <= ruleset.bucket_cap(bucket), bucket
    assert result.raw_score <= ruleset.max_score


def test_overlapping_symptoms_are_discounted(ruleset):
    """origin_exposed, no_waf, and unprotected are three views of one fact.
    Scoring all three in full would triple-count it."""
    _record, result = scored(ruleset, origin_exposed=True, no_waf=True,
                             unprotected=True)
    protection = [c for c in result.contributions if c.family == "protection"]
    assert len(protection) >= 3
    assert sum(1 for c in protection if c.family_discounted) >= 2
    assert sum(1 for c in protection if not c.family_discounted) == 1


def test_independent_concerns_are_not_discounted_against_each_other(ruleset):
    """A non-production system being public and a WAF being bypassable are
    unrelated facts, so they must sit in different families."""
    _record, result = scored(ruleset, cdn_bypass_candidate=True,
                             is_nonprod_exposed=True, env="dev")
    families = {c.rule_id: c.family for c in result.contributions}
    assert families.get("WAF_BYPASSABLE") != families.get("NONPROD_INTERNET_FACING")


# ── Exclusions and modifiers ────────────────────────────────────────────────

def test_scan_artifacts_are_excluded_entirely(ruleset):
    _record, result = scored(ruleset, scan_artifact=True, origin_exposed=True,
                             no_waf=True)
    assert result.excluded
    assert result.score == 0
    assert result.excluded_by == "EXCL_SCAN_ARTIFACT"
    assert not result.contributions


def test_waf_reduces_but_does_not_erase(ruleset):
    bare = scored(ruleset, origin_exposed=True, no_waf=True)[1]
    behind_waf = scored(ruleset, origin_exposed=True, no_waf=True,
                        response_class="waf_blocked", waf_blocked=True)[1]
    assert behind_waf.score < bare.score
    assert behind_waf.mitigated is True


def test_stacked_modifiers_cannot_annihilate_a_score(ruleset):
    """A WAF (x0.45) on a Cloudflare alias port (x0.25) compounds to x0.11 and
    would erase the finding. The product is clamped."""
    _record, result = scored(
        ruleset, response_class="waf_blocked", waf_blocked=True,
        cf_alias_port=True, cdn_name="cloudflare", port=2082,
        mgmt_surface=True, remote_access_exposed=True)
    product = 1.0
    for modifier in result.modifiers:
        product *= modifier.factor
    assert product < ruleset.modifier_floor, "test needs stacked modifiers"
    assert result.score >= int(result.raw_score * ruleset.modifier_floor) - 1
    assert result.score > 0


def test_modifiers_state_their_reason(ruleset):
    _record, result = scored(ruleset, response_class="waf_blocked",
                             waf_blocked=True, mgmt_surface=True)
    assert result.modifiers
    for modifier in result.modifiers:
        assert modifier.reason, "a silent modifier is indistinguishable from a bug"


# ── Severity floor ──────────────────────────────────────────────────────────

def test_unmitigated_critical_is_floored(ruleset, cfg):
    """A critical rule with nothing mitigating it cannot land in a trivial band."""
    _record, result = scored(ruleset, cdn_bypass_candidate=True)
    assert result.worst_severity == "critical"
    assert not result.mitigated
    assert ruleset.band_rank(result.band) <= ruleset.band_rank(ruleset.severity_floor)


def test_mitigated_critical_is_not_floored(ruleset):
    """The floor must not fire when a WAF is genuinely blocking the request.

    Without this exception the floor put a third of the estate in "high" and the
    band carried no information. The finding still reports critical severity, so
    nothing is concealed.
    """
    _record, result = scored(ruleset, cdn_bypass_candidate=True,
                             response_class="waf_blocked", waf_blocked=True)
    assert result.worst_severity == "critical"
    assert result.mitigated is True
    assert result.floored_from == ""


def test_band_and_worst_severity_are_separate_questions(ruleset):
    """A WAF-protected endpoint running end-of-life software has a modest band
    and a critical worst issue. Reporting only one of those misleads."""
    _record, result = scored(
        ruleset, response_class="waf_blocked", waf_blocked=True,
        cdn_bypass_candidate=True)
    assert result.worst_severity == "critical"
    assert result.band != "critical"


# ── Lifecycle derivation ────────────────────────────────────────────────────

def test_eol_detected_from_cpe(ruleset):
    record = base(cpe_products=["microsoft:windows_server_2003"])
    derive_lifecycle(record, ruleset.lifecycle, today=date(2026, 7, 25))
    assert record["eol_count"] == 1
    assert record["eol_worst_severity"] == "critical"
    assert record["eol_years_past"] == pytest.approx(11.0, abs=0.2)
    assert "Windows Server 2003" in record["eol_summary"]


def test_eol_detected_from_webserver_regex(ruleset):
    record = base(webserver="Microsoft-IIS/6.0")
    derive_lifecycle(record, ruleset.lifecycle, today=date(2026, 7, 25))
    assert record["eol_count"] >= 1


def test_current_software_is_not_flagged_eol(ruleset):
    record = base(webserver="nginx/1.27.0", cpe_products=[])
    derive_lifecycle(record, ruleset.lifecycle)
    assert record["eol_count"] == 0
    assert record["eol_years_past"] == 0.0


def test_outdated_component_detected(ruleset):
    record = base(tech_versions={"jQuery": "1.8.3"})
    derive_lifecycle(record, ruleset.lifecycle)
    assert record["outdated_count"] == 1
    assert "jQuery" in record["outdated_summary"]


def test_current_component_not_flagged(ruleset):
    record = base(tech_versions={"jQuery": "3.7.1"})
    derive_lifecycle(record, ruleset.lifecycle)
    assert record["outdated_count"] == 0


@pytest.mark.parametrize("left,right,expected", [
    ("1.8.3", "3.7.1", True),
    ("3.7.1", "3.7.1", False),
    ("3.8.0", "3.7.1", False),
    ("10.0", "9.0", False),
    ("2.4.1", "2.4.58", True),
])
def test_version_comparison(left, right, expected):
    assert version_lt(left, right) is expected


def test_vuln_family_carries_possible_confidence(ruleset):
    _record, result = scored(ruleset, cpe_products=["n8n:n8n"])
    entry = next(c for c in result.contributions
                 if c.rule_id == "SUSPECTED_VULN_FAMILY")
    assert entry.confidence == "possible"
    assert "not a confirmed vulnerability" in entry.why


# ── Takeover grading ────────────────────────────────────────────────────────

def test_cloudflare_530_grades_as_likely_dangling(ruleset):
    record = base(origin_health="dns_missing", cf_error_code=1016,
                  status_code=530, edge_provider="Cloudflare")
    derive_takeover(record, ruleset.takeover)
    assert record["takeover_grade"] == "high"
    assert record["takeover_confidence"] == "probable"
    assert record["takeover_evidence"]


def test_525_broken_origin_is_not_a_takeover(ruleset):
    """525 means the origin answers but its TLS is broken. Grading it as a
    takeover would generate false alerts."""
    record = base(origin_health="tls_broken", status_code=525)
    derive_takeover(record, ruleset.takeover)
    assert record["takeover_grade"] == ""


def test_azure_dangling_fingerprint(ruleset):
    record = base(cname=["gone.azurewebsites.net"], status_code=404,
                  title="Web App - Unavailable")
    derive_takeover(record, ruleset.takeover)
    assert record["takeover_grade"] == "high"
    assert record["takeover_provider"] == "Azure App Service"


def test_serving_third_party_host_is_not_a_takeover_candidate(ruleset):
    record = base(cname=["live.azurewebsites.net"], status_code=200,
                  title="My Application")
    derive_takeover(record, ruleset.takeover)
    assert record["takeover_grade"] == ""


def test_takeover_is_never_asserted_as_confirmed(ruleset):
    """Confirming a takeover needs a live DNS and provider check, which ingest
    deliberately does not perform."""
    record = base(origin_health="dns_missing", status_code=530)
    derive_takeover(record, ruleset.takeover)
    assert record["takeover_confidence"] != "confirmed"


# ── Host rollup and index ───────────────────────────────────────────────────

def test_host_score_is_worst_endpoint_not_average(ruleset):
    """A host with one terrible endpoint and nine clean ones is not 90% healthy."""
    bad = scored(ruleset, cdn_bypass_candidate=True, origin_exposed=True,
                 no_waf=True, unprotected=True)[1]
    clean = [scored(ruleset)[1] for _ in range(9)]
    summary = score_host([bad, *clean])
    assert summary["worst"] == bad.score
    assert summary["score"] >= bad.score


def test_host_score_rewards_breadth_of_problems(ruleset):
    one_problem = scored(ruleset, origin_exposed=True)[1]
    many = scored(ruleset, origin_exposed=True, no_waf=True, unprotected=True,
                  mgmt_surface=True, version_disclosure=True,
                  webserver="Microsoft-IIS/10.0", api_surface=True)[1]
    assert score_host([many])["score"] > score_host([one_problem])["score"]


def test_excluded_endpoints_do_not_drag_the_index(ruleset):
    real = [scored(ruleset, origin_exposed=True, no_waf=True)[1]]
    artefacts = [scored(ruleset, scan_artifact=True)[1] for _ in range(50)]
    with_artefacts = residual_risk_index(real + artefacts, ruleset)
    without = residual_risk_index(real, ruleset)
    assert with_artefacts["index"] == without["index"]
    assert with_artefacts["endpoints"] == 1


def test_residual_index_publishes_its_formula(ruleset):
    result = residual_risk_index([scored(ruleset)[1]], ruleset)
    assert result["formula"], "an index nobody can reproduce is worse than none"


# ── Predicate evaluator ─────────────────────────────────────────────────────

@pytest.mark.parametrize("node,record,expected", [
    ({"field": "a", "op": "truthy"}, {"a": True}, True),
    ({"field": "a", "op": "truthy"}, {"a": 0}, False),
    ({"field": "a", "op": "truthy"}, {"a": ""}, False),
    ({"field": "a", "op": "truthy"}, {"a": "none"}, False),
    ({"field": "a", "op": "eq", "value": True}, {"a": 1}, True),
    ({"field": "a", "op": "eq", "value": "x"}, {"a": "X"}, True),
    ({"field": "a", "op": "gte", "value": 5}, {"a": 5}, True),
    ({"field": "a", "op": "gte", "value": 5}, {"a": None}, False),
    ({"field": "a", "op": "in", "value": ["x", "y"]}, {"a": "y"}, True),
    ({"field": "a", "op": "contains_any", "value": ["p"]}, {"a": ["P", "q"]}, True),
    ({"field": "a", "op": "contains_all", "value": ["p", "q"]}, {"a": ["p"]}, False),
    ({"field": "a", "op": "matches", "value": "^ab"}, {"a": "ABC"}, True),
    ({"all": [{"field": "a", "op": "truthy"}, {"field": "b", "op": "truthy"}]},
     {"a": 1, "b": 0}, False),
    ({"any": [{"field": "a", "op": "truthy"}, {"field": "b", "op": "truthy"}]},
     {"a": 1, "b": 0}, True),
    ({"not": {"field": "a", "op": "truthy"}}, {"a": 0}, True),
])
def test_predicate_evaluation(node, record, expected):
    assert predicate.evaluate(node, record) is expected


def test_predicate_rejects_unknown_operator():
    with pytest.raises(predicate.PredicateError):
        predicate.evaluate({"field": "a", "op": "sudo_rm"}, {"a": 1})


def test_predicate_has_no_eval():
    """Rules are data. A rules file must never be able to execute code."""
    import pathlib as _pathlib
    source = _pathlib.Path(predicate.__file__).read_text(encoding="utf-8")
    # re.compile is fine — it compiles a regex, not Python. These are the calls
    # that would turn a config file into an execution vector.
    for forbidden in ("eval(", "exec(", "__import__(", "compile(source",
                      "subprocess", "os.system", "pickle"):
        assert forbidden not in source, f"predicate.py must not use {forbidden}"


def test_predicate_describes_itself_readably():
    text = predicate.describe(
        {"all": [{"field": "no_waf", "op": "truthy"},
                 {"field": "port", "op": "gte", "value": 8000}]})
    assert "no waf is set" in text
    assert "port is at least 8000" in text


# ── Rule set validation ─────────────────────────────────────────────────────

def test_shipped_ruleset_is_valid(ruleset):
    assert validate_ruleset(ruleset) == []
    assert ruleset.rules
    assert rules_fingerprint(ruleset)


def test_every_actionable_rule_explains_itself(ruleset):
    """A finding a reader cannot act on is noise."""
    for rule in ruleset.rules:
        if rule.is_positive or rule.severity == "info":
            continue
        assert rule.why, f"{rule.id} has no `why`"
        assert rule.remediation, f"{rule.id} has no `remediation`"
        assert rule.exec_line, f"{rule.id} has no `exec_line`"


def test_rule_referencing_an_unknown_field_is_rejected(ruleset):
    broken = RuleSet(
        version=1, max_score=100, bands=ruleset.bands, buckets=ruleset.buckets,
        severity_floor=None, overlap_factor=0.3,
        rules=[Rule(id="BAD", family="x", bucket="exposure", severity="high",
                    confidence="confirmed",
                    when={"field": "typo_field_name", "op": "truthy"},
                    title="t", why="w", remediation="r", exec_line="e",
                    points=1)],
        modifiers=[], exclusions=[])
    problems = validate_ruleset(broken)
    assert any("unknown field" in p for p in problems)


def test_rule_with_two_weight_specs_is_rejected(ruleset):
    broken = RuleSet(
        version=1, max_score=100, bands=ruleset.bands, buckets=ruleset.buckets,
        severity_floor=None, overlap_factor=0.3,
        rules=[Rule(id="BAD", family="x", bucket="exposure", severity="high",
                    confidence="confirmed", when={"field": "no_waf", "op": "truthy"},
                    title="t", why="w", remediation="r", exec_line="e",
                    points=5, map_spec={"field": "env", "values": {}})],
        modifiers=[], exclusions=[])
    assert any("exactly one of" in p for p in validate_ruleset(broken))


def test_fingerprint_changes_when_a_weight_changes(cfg, ruleset):
    """A run records this hash, so a score delta caused by re-scoring can be told
    apart from a real-world change."""
    from dataclasses import replace
    original = rules_fingerprint(ruleset)
    bumped = RuleSet(
        version=ruleset.version, max_score=ruleset.max_score, bands=ruleset.bands,
        buckets=ruleset.buckets, severity_floor=ruleset.severity_floor,
        overlap_factor=ruleset.overlap_factor,
        rules=[replace(ruleset.rules[0], points=(ruleset.rules[0].points or 0) + 1),
               *ruleset.rules[1:]],
        modifiers=ruleset.modifiers, exclusions=ruleset.exclusions)
    assert rules_fingerprint(bumped) != original


def test_no_rule_fires_on_nearly_everything(cfg, ruleset):
    """A rule that fires on every endpoint is mis-modelled, not a finding."""
    from pathlib import Path

    from frogscope.ingest import pipeline

    fixture = Path(__file__).parent / "fixtures" / "sample.csv"
    records, _rollups, _load, _collapse, _entities = pipeline.analyse(fixture, cfg)
    scoreable = [r for r in records if not r.get("scan_artifact")]
    assert scoreable

    counts: dict[str, int] = {}
    for record in scoreable:
        result = score_record(record, ruleset)
        for entry in result.contributions:
            if entry.family == "positive":
                continue
            counts[entry.rule_id] = counts.get(entry.rule_id, 0) + 1

    for rule_id, count in counts.items():
        share = 100 * count / len(scoreable)
        assert share <= 95, (
            f"{rule_id} fires on {share:.0f}% of endpoints — that is a "
            f"mis-modelled rule, not a finding"
        )


def test_weights_are_config_driven_not_hardcoded(cfg, tmp_path, ruleset):
    """Changing a YAML weight must move the score with no code edit."""
    import shutil

    import yaml

    staging = tmp_path / "config"
    shutil.copytree(cfg.config_dir, staging)
    rules_path = staging / "rules.yaml"
    raw = yaml.safe_load(rules_path.read_text())
    for entry in raw["rules"]:
        if entry["id"] == "NO_WAF":
            entry["points"] = 39
            break
    rules_path.write_text(yaml.safe_dump(raw, sort_keys=False))

    louder = load_ruleset(staging)
    quiet = score_record(base(no_waf=True), ruleset)
    loud = score_record(base(no_waf=True), louder)
    assert loud.score > quiet.score


# ── Findings ────────────────────────────────────────────────────────────────

def test_findings_dedupe_per_rule_and_host(cfg, ruleset):
    """One Cloudflare-fronted host must not produce the same finding once per
    alias port."""
    from frogscope.scoring.findings import build_findings

    scored_pairs = []
    for port in (80, 443, 2052, 2082, 2086, 2095, 8080, 8880):
        record = base(host="one.example.com", port=port, no_waf=True,
                      origin_exposed=True)
        record["endpoint_key"] = f"one.example.com:{port}"
        derive_scoring_inputs(record, ruleset.lifecycle, ruleset.takeover)
        scored_pairs.append((record, score_record(record, ruleset)))

    findings = build_findings(scored_pairs)
    keys = [f.dedup_key for f in findings]
    assert len(keys) == len(set(keys))
    no_waf = next(f for f in findings if f.rule_id == "NO_WAF")
    assert no_waf.endpoint_count == 8
    assert no_waf.host_count == 1


def test_finding_severity_is_the_rule_not_the_score(cfg, ruleset):
    """A critical rule on an otherwise unremarkable host must still page someone."""
    from frogscope.scoring.findings import build_findings

    record = base(host="quiet.example.com", cdn_bypass_candidate=True)
    record["endpoint_key"] = "quiet.example.com:443"
    derive_scoring_inputs(record, ruleset.lifecycle, ruleset.takeover)
    result = score_record(record, ruleset)
    findings = build_findings([(record, result)])

    critical = next(f for f in findings if f.rule_id == "WAF_BYPASSABLE")
    assert critical.severity == "critical"
    assert result.score < 65, "the point is that the score is modest"


def test_excluded_endpoints_produce_no_findings(cfg, ruleset):
    from frogscope.scoring.findings import build_findings

    record = base(scan_artifact=True, no_waf=True, origin_exposed=True)
    record["endpoint_key"] = "a.example.com:2053"
    derive_scoring_inputs(record, ruleset.lifecycle, ruleset.takeover)
    assert build_findings([(record, score_record(record, ruleset))]) == []


# ── Placeholder rendering (regression) ──────────────────────────────────────

def test_an_unfillable_placeholder_is_removed_not_shown():
    """`_render` used to leave `{vuln_summary}` in place when the field was empty.
    A visible placeholder reads as a broken template and costs credibility on every
    other number on the page."""
    from frogscope.scoring.engine import _render

    out = _render("{vuln_summary}. This is a banner fingerprint, not proof.", {})
    assert "{" not in out
    assert out.startswith("This is a banner fingerprint")


def test_a_fillable_placeholder_is_substituted():
    from frogscope.scoring.engine import _render

    out = _render("{vuln_summary}. This is a banner fingerprint.",
                  {"vuln_summary": "Citrix Gateway"})
    assert out.startswith("Citrix Gateway.")


def test_removing_a_placeholder_leaves_readable_text():
    """Dropping the token can leave dangling punctuation or an empty parenthetical."""
    from frogscope.scoring.engine import _render

    assert "(" not in _render("Past end of life ({eol_years_past} years).", {})
    assert "  " not in _render("A {a} and a {b} walk in.", {})
    assert _render("{x}, which matters.", {}).startswith("Which matters")


def test_remediation_placeholders_are_rendered_too():
    """`remediation` was passed through raw, so a placeholder there reached the UI
    verbatim."""
    import inspect

    from frogscope.scoring import engine

    source = inspect.getsource(engine)
    assert "remediation=_render(rule.remediation, record)" in source


def test_rule_definitions_shown_without_a_record_describe_their_placeholders():
    """The Methodology view lists rule DEFINITIONS with no endpoint to fill them, so
    a raw `{vuln_summary}` there looked like a bug rather than a slot."""
    from frogscope.scoring.rules import describe_template

    out = describe_template("{vuln_summary}. This is a banner fingerprint.")
    assert "{" not in out
    assert out.startswith("The product family")


def test_every_placeholder_used_by_a_rule_has_a_human_label():
    """A missing label falls back to the raw field name, which reads like jargon."""
    import re
    from pathlib import Path

    import yaml

    from frogscope.scoring.rules import PLACEHOLDER_LABELS

    doc = yaml.safe_load(Path("config/rules.yaml").read_text(encoding="utf-8"))
    used = set()
    for rule in doc["rules"]:
        blob = " ".join(str(rule.get(k) or "")
                        for k in ("why", "exec_line", "remediation", "title"))
        used.update(re.findall(r"\{([a-z_]+)\}", blob))
    missing = sorted(used - set(PLACEHOLDER_LABELS))
    assert missing == [], f"add these to PLACEHOLDER_LABELS: {missing}"
