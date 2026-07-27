"""Classification tests.

The classifiers decide whether the dashboard shows signal or noise. In a
default-flag httpx scan roughly a third of rows are artefacts of probing
TLS-only ports over cleartext, and most of the remaining ports on a
Cloudflare-fronted host are aliases of one site — so getting these wrong
inflates the reported attack surface several-fold.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from frogscope.config import load_config
from frogscope.ingest import classify
from frogscope.ingest.enrich import enrich


@pytest.fixture(scope="module")
def cfg():
    return load_config()


def make(**kw):
    base = {
        "endpoint_key": "x.example.com:443", "host": "x.example.com",
        "host_display": "x.example.com", "port": 443, "scheme": "https",
        "status_code": 200, "title": "", "content_type": "text/html",
        "content_length": 5000, "words": 100, "lines": 20, "response_ms": 100.0,
        "webserver": "", "final_url": "", "redirect_chain": [], "host_ip": "1.2.3.4",
        "a": ["1.2.3.4"], "aaaa": [], "cname": [], "resolvers": [], "cdn": False,
        "cdn_name": "", "cdn_type": "", "tech": [], "cpe": [], "cpe_products": [],
        "wp_plugins": [], "wp_themes": [], "scanned_at": "2026-07-25T07:00:00+00:00",
        "probe_count": 1, "intra_run_inconsistent": False,
        "inconsistent_fields": [], "scheme_conflict": False, "raw": {}, "extra": {},
    }
    base.update(kw)
    base["endpoint_key"] = f"{base['host']}:{base['port']}"
    return base


def one(cfg, **kw):
    rec = make(**kw)
    enrich([rec], cfg)
    return rec


# ── Scan artefacts ──────────────────────────────────────────────────────────

def test_tls_port_probed_over_http_is_an_artefact_not_a_finding(cfg):
    """Cloudflare's nginx returning 400 here is CORRECT behaviour. Scoring it
    would let one meaningless class dominate the dashboard."""
    rec = one(cfg, port=2053, scheme="http", status_code=400,
              title="400 The plain HTTP request was sent to HTTPS port")
    assert rec["response_class"] == "scan_artifact"
    assert rec["scan_artifact"] is True
    assert rec["serves_content"] is False


def test_artefact_is_excluded_from_cleartext_findings(cfg):
    rec = one(cfg, port=8443, scheme="http", status_code=400,
              title="400 The plain HTTP request was sent to HTTPS port")
    assert rec["no_tls_redirect"] is False


# ── Cloudflare alias ports ──────────────────────────────────────────────────

def test_cloudflare_alias_port_is_marked(cfg):
    rec = one(cfg, port=2082, cdn_name="cloudflare", cdn=True, cdn_type="waf")
    assert rec["cf_alias_port"] is True


def test_same_port_on_a_non_cloudflare_host_is_a_real_service(cfg):
    """8080 is both a Cloudflare alias port and a common app-server port. Only
    the Cloudflare case is an alias."""
    rec = one(cfg, port=8080, cdn_name="", cdn=False)
    assert rec["cf_alias_port"] is False


def test_standard_ports_are_never_aliases(cfg):
    rec = one(cfg, port=443, cdn_name="cloudflare", cdn=True)
    assert rec["cf_alias_port"] is False


# ── Cloudflare origin errors: takeover vs broken origin ─────────────────────

def test_530_is_a_missing_origin_and_therefore_a_takeover_signal(cfg):
    rec = one(cfg, status_code=530, cdn_name="cloudflare", cdn=True, cdn_type="waf")
    assert rec["origin_health"] == "dns_missing"
    assert rec["cf_error_code"] == 1016
    assert rec["response_class"] == "origin_unreachable"


def test_525_is_a_broken_origin_not_a_takeover(cfg):
    """Conflating these two produces false takeover alerts."""
    rec = one(cfg, status_code=525, cdn_name="cloudflare", cdn=True, cdn_type="waf")
    assert rec["origin_health"] == "tls_broken"
    assert rec["response_class"] == "origin_tls_failure"
    assert rec["origin_health"] != "dns_missing"


def test_5xx_without_cloudflare_is_just_a_server_error(cfg):
    rec = one(cfg, status_code=530, cdn_name="", cdn=False)
    assert rec["origin_health"] == "ok"
    assert rec["response_class"] == "server_error"


# ── WAF ─────────────────────────────────────────────────────────────────────

def test_cloudflare_block_page_is_classified_as_blocked(cfg):
    rec = one(cfg, status_code=403, cdn_name="cloudflare", cdn=True,
              title="Attention Required! | Cloudflare")
    assert rec["response_class"] == "waf_blocked"
    assert rec["waf_blocked"] is True


def test_cloudflare_challenge_is_distinct_from_a_block(cfg):
    rec = one(cfg, status_code=503, cdn_name="cloudflare", cdn=True,
              title="Just a moment...")
    assert rec["response_class"] == "waf_challenge"


# ── Environment inference ───────────────────────────────────────────────────

@pytest.mark.parametrize("host,expected", [
    ("uat-learning-hub.example.com", "uat"),
    ("dev.example.com", "dev"),
    ("qa-portal.example.com", "test"),
    ("staging.example.com", "staging"),
    ("sandbox.example.com", "sandbox"),
    ("www.example.com", "prod"),
])
def test_env_inferred_from_hostname_tokens(cfg, host, expected):
    """Only industry-general tokens. An organisation's private shorthand must not
    be in the shipped defaults, or it mis-labels every other estate that happens
    to use the same string."""
    assert classify.env_of(host, cfg)[0] == expected


def test_shipped_defaults_carry_no_organisation_specific_tokens(cfg):
    """These were once shipped for everyone. `cftest` and `it2ta` mean something
    at exactly one company and nothing anywhere else."""
    for token in ("cftest", "it2ta", "it2tauat", "tauat"):
        assert token not in cfg.env_lookup, (
            f"{token!r} is one organisation's naming — it belongs in "
            f"env.custom_keywords, not in the defaults")


def test_a_site_can_add_its_own_naming_without_editing_python(tmp_path):
    """The replacement for hardcoding: an overlay merged on top of the defaults."""
    import shutil

    import yaml

    from frogscope.config import load_config

    shutil.copytree(Path("config"), tmp_path / "config")
    path = tmp_path / "config" / "classify.yaml"
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    doc["env"]["custom_keywords"] = {"test": ["cftest"], "ta": ["it2ta"],
                                     "uat": ["it2tauat"]}
    path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")

    custom = load_config(tmp_path / "config", tmp_path / "data")
    assert classify.env_of("agtech-olf-cftest.example.com", custom)[0] == "test"
    assert classify.env_of("host.it2ta.example.com", custom)[0] == "ta"
    assert classify.env_of("host.it2tauat.example.com", custom)[0] == "uat"
    # And the generic tokens still work alongside the overlay.
    assert classify.env_of("uat.example.com", custom)[0] == "uat"


def test_env_matches_whole_tokens_not_substrings(cfg):
    """'data' contains 'ta'; 'latest' contains 'test'. Substring matching would
    mislabel both."""
    assert classify.env_of("data.example.com", cfg)[0] != "ta"
    assert classify.env_of("latest.example.com", cfg)[0] != "test"


def test_unknown_env_is_unclassified_not_prod(cfg):
    """Defaulting to prod would silently overstate production exposure."""
    env, _ = classify.env_of("acrolinx.example.com", cfg)
    assert env == "unclassified"


def test_env_records_the_token_that_matched(cfg):
    _env, token = classify.env_of("uat-learning-hub.example.com", cfg)
    assert token == "uat"


# ── Provider resolution ─────────────────────────────────────────────────────

def test_most_specific_provider_in_the_chain_wins(cfg):
    """A chain through Entra App Proxy that terminates at Traffic Manager is
    both. The App Proxy fact is the actionable one and must not be discarded
    just because it sits earlier in the chain."""
    rec = one(cfg, cname=[
        "aes-confluence-int-x.msappproxy.net",
        "cwap-nam1-runtime.routing.msappproxy.net",
        "nam.proxy-3.appproxy.msidentity.com",
        "www.tm.nam.proxy-3.appproxy.trafficmanager.net",
    ])
    assert rec["hosting_provider"] == "Entra ID App Proxy"
    assert rec["edge_provider"] == "Azure Traffic Manager"
    assert rec["azure_app_proxy"] is True


def test_longest_suffix_wins_over_shorter(cfg):
    rec = one(cfg, cname=["foo.cdn.cloudflare.net"])
    assert rec["hosting_provider"] == "Cloudflare"
    assert rec["hosting_kind"] == "waf"


# ── Protection: three separate questions ────────────────────────────────────

def test_waf_and_direct_exposure_are_not_the_same_question(cfg):
    """A WP Engine or App Proxy endpoint has no WAF but is not 'reached
    directly'. Collapsing the two tells an executive that a pre-authenticated
    endpoint is an unprotected origin."""
    rec = one(cfg, cname=["x.wpeproxy.com"])
    assert rec["no_waf"] is True
    assert rec["origin_exposed"] is False
    assert rec["behind_proxy"] is True


def test_a_truly_direct_origin_is_flagged_both_ways(cfg):
    rec = one(cfg, cname=[], cdn=False, cdn_name="")
    assert rec["origin_exposed"] is True
    assert rec["no_waf"] is True
    assert rec["origin_exposure_reason"]


def test_cloudflare_fronted_endpoint_is_neither(cfg):
    rec = one(cfg, cdn=True, cdn_name="cloudflare", cdn_type="waf")
    assert rec["waf_protected"] is True
    assert rec["origin_exposed"] is False
    assert rec["no_waf"] is False


def test_app_proxy_counts_as_a_defence_layer(cfg):
    """It pre-authenticates, so it protects even though it is not a WAF."""
    rec = one(cfg, cname=["x.msappproxy.net"], scheme="https")
    assert rec["defence_layers"] >= 2


# ── Cross-row derivations ───────────────────────────────────────────────────

def test_waf_bypass_candidate_needs_both_conditions(cfg):
    """One host with a WAF-fronted 443 and a directly-exposed second port: the
    WAF can be bypassed. Nothing in the raw CSV surfaces this."""
    protected = make(host="h.example.com", port=443, cdn=True,
                     cdn_name="cloudflare", cdn_type="waf", status_code=403,
                     title="Attention Required! | Cloudflare")
    direct = make(host="h.example.com", port=8081, cdn=False, cdn_name="",
                  status_code=200)
    enrich([protected, direct], cfg)
    assert direct["origin_exposed"] is True
    assert protected["cdn_bypass_candidate"] is True
    assert direct["cdn_bypass_candidate"] is True


def test_shared_ip_blast_radius_is_counted(cfg):
    records = [make(host=f"h{i}.example.com", port=443, host_ip="9.9.9.9")
               for i in range(6)]
    enrich(records, cfg)
    assert records[0]["ip_cluster_size"] == 6
    assert records[0]["shared_infra"] is True


def test_identical_content_is_clustered(cfg):
    records = [make(host=f"h{i}.example.com", port=443,
                    title="ION Environment Manager", content_length=703)
               for i in range(4)]
    enrich(records, cfg)
    assert records[0]["content_cluster_size"] == 4
    assert len({r["content_sig"] for r in records}) == 1


# ── Auth surfaces ───────────────────────────────────────────────────────────

def test_federated_login_is_detected_and_marked_as_federated(cfg):
    rec = one(cfg, title="Sign in to your account",
              final_url="https://login.microsoftonline.com/x/oauth2/authorize")
    assert rec["auth_surface_type"] == "m365"
    assert rec["federated_auth"] is True
    assert rec["response_class"] == "auth_required"


def test_management_console_is_flagged(cfg):
    rec = one(cfg, title="ION Environment Manager")
    assert rec["mgmt_surface"] is True


def test_remote_access_appliance_detected_from_cpe(cfg):
    rec = one(cfg, cpe_products=["cisco:adaptive-security-appliance-software"])
    assert rec["remote_access_exposed"] is True


# ── Technology parsing ──────────────────────────────────────────────────────

def test_webserver_version_is_split_and_disclosure_flagged(cfg):
    rec = one(cfg, webserver="Microsoft-IIS/10.0")
    assert rec["webserver_family"] == "Microsoft-IIS"
    assert rec["webserver_version"] == "10.0"
    assert rec["version_disclosure"] is True


def test_webserver_without_a_version_is_not_a_disclosure(cfg):
    rec = one(cfg, webserver="cloudflare")
    assert rec["version_disclosure"] is False


def test_tech_versions_are_extracted(cfg):
    rec = one(cfg, tech=["IIS:10.0", "Yoast SEO:28.1", "HSTS"])
    assert rec["tech_versions"] == {"IIS": "10.0", "Yoast SEO": "28.1"}
    assert "HSTS" in rec["tech_names"]
    assert rec["hsts_present"] is True
