"""The scan path: option validation, argv construction, and the safety gates.

Nothing here starts a scanner. These tests cover the parts that decide *whether*
and *what* to run, which is where a mistake is dangerous — command injection, or
traffic sent to somebody who did not agree to it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from frogscope.scan import options as opts
from frogscope.scan import tools
from frogscope.scan.runner import ScanRun, _https_targets_from_csv

# ── Nothing typed in a browser may reach a command line ─────────────────────

@pytest.mark.parametrize("hostile", [
    "example.com; rm -rf /",
    "example.com && curl evil.test",
    "$(whoami).com",
    "`id`.com",
    "example.com | tee /tmp/x",
    "-oN /etc/passwd",
    "--output=/etc/shadow",
    "example.com\nsecond.com; id",
    "../../etc/passwd",
    "example.com'\"",
    "*.example.com",
])
def test_shell_metacharacters_never_survive_validation(hostile):
    """The domain pattern is the boundary. If something dangerous gets past it, it
    reaches an argv entry — so this is the test that matters most in this file."""
    with pytest.raises(opts.OptionError):
        opts.parse({"domains": [hostile], "authorised": True})


@pytest.mark.parametrize("address,kind", [
    ("192.168.0.0/16", "cidr"), ("10.0.0.1", "ip"),
    ("203.0.113.0/24", "cidr"), ("127.0.0.1", "ip"),
])
def test_an_address_or_range_is_classified_not_treated_as_a_domain(address, kind):
    """Digits are valid hostname characters, so `192.168.0.0/16` used to pass
    validation as the "domain" 192.168.0.0 with the /16 silently dropped —
    leaving somebody convinced they had scanned a range. v2 accepts IPs and
    CIDR ranges as their own target kind instead of refusing them, but they
    must land in `ips`/`cidrs`, never be misread as a domain."""
    parsed = opts.parse({"targets": [address], "authorised": True})
    assert parsed.domains == []
    assert parsed.target_kind == kind
    if kind == "ip":
        assert parsed.ips == [address]
    else:
        assert parsed.cidrs == [address]


def test_an_oversized_cidr_is_refused_outright():
    """A /8 is 16.7 million addresses — refused at parse time, with a real
    explanation, rather than only failing after mapcidr has already expanded
    it."""
    with pytest.raises(opts.OptionError) as caught:
        opts.parse({"targets": ["10.0.0.0/8"], "authorised": True})
    assert "ceiling" in str(caught.value)


def test_mixed_targets_classify_as_mixed():
    parsed = opts.parse({
        "targets": ["example.com", "203.0.113.5", "198.51.100.0/28"],
        "authorised": True,
    })
    assert parsed.target_kind == "mixed"
    assert parsed.domains == ["example.com"]
    assert parsed.ips == ["203.0.113.5"]
    assert parsed.cidrs == ["198.51.100.0/28"]


def test_a_pasted_url_is_reduced_to_its_host():
    """Convenience without loosening the pattern: the scheme and path are stripped
    and the remainder still has to be a valid domain."""
    parsed = opts.parse({"domains": ["https://example.com/a/b"],
                         "authorised": True})
    assert parsed.domains == ["example.com"]


def test_valid_domains_are_accepted_and_deduplicated():
    parsed = opts.parse({"domains": "example.com, EXAMPLE.com\nsub.example.org",
                         "authorised": True})
    assert parsed.domains == ["example.com", "sub.example.org"]


def test_every_numeric_bound_is_enforced():
    """An unbounded rate limit against someone else's estate is a denial of
    service, not a preference."""
    for key, value in (("rate_limit", 100_000), ("rate_limit", 0),
                       ("threads", 5000), ("timeout", 600), ("retries", 99)):
        with pytest.raises(opts.OptionError):
            opts.parse({"domains": ["example.com"], "authorised": True,
                        key: value})


def test_a_non_numeric_bound_is_refused():
    with pytest.raises(opts.OptionError):
        opts.parse({"domains": ["example.com"], "authorised": True,
                    "rate_limit": "lots"})


def test_an_unknown_port_profile_is_refused():
    with pytest.raises(opts.OptionError):
        opts.parse({"domains": ["example.com"], "authorised": True,
                    "profile": "everything"})


# ── Consent ─────────────────────────────────────────────────────────────────

def test_a_scan_without_authorisation_is_refused():
    with pytest.raises(opts.OptionError) as caught:
        opts.parse({"domains": ["example.com"], "authorised": False})
    assert "authorised" in str(caught.value)


def test_authorisation_is_not_implied_by_omission():
    with pytest.raises(opts.OptionError):
        opts.parse({"domains": ["example.com"]})


def test_a_real_domain_portfolio_is_accepted():
    """A company of any size holds live brands, country domains, defensive
    registrations and parked names. The old 50-domain cap forced that list to be
    split across projects, fragmenting the very history the tool builds."""
    many = [f"brand{n}.example.com" for n in range(400)]
    parsed = opts.parse({"domains": many, "authorised": True})
    assert len(parsed.domains) == 400


def test_the_domain_ceiling_is_a_sanity_check_not_a_policy():
    """It exists to catch a pasted-in file, and says so rather than telling somebody
    their portfolio is too big."""
    assert opts.MAX_DOMAINS >= 1000
    many = [f"h{n}.example.com" for n in range(opts.MAX_DOMAINS + 1)]
    with pytest.raises(opts.OptionError) as caught:
        opts.parse({"domains": many, "authorised": True})
    assert "ceiling" in str(caught.value)


def test_host_count_is_the_limit_that_actually_gates_traffic():
    """Domain count costs enumeration time; host count decides how much traffic is
    sent. The approval gate is on hosts, and matters more as the list grows."""
    assert opts.CONFIRM_ABOVE < opts.MAX_HOSTS
    assert opts.MAX_HOSTS >= 100_000, \
        "a few hundred domains legitimately resolve to far more hosts than one"


def test_no_domains_is_refused():
    with pytest.raises(opts.OptionError):
        opts.parse({"domains": [], "authorised": True})


# ── argv construction ───────────────────────────────────────────────────────

def test_httpx_argv_is_a_list_of_separate_arguments():
    """A list, never a string. A string would need a shell to interpret it, and a
    shell is what turns a hostname into a command."""
    parsed = opts.parse({"domains": ["example.com"], "authorised": True})
    argv = opts.httpx_argv("/usr/bin/httpx", parsed,
                           input_path="/tmp/in.txt", output_path="/tmp/out.csv")
    assert isinstance(argv, list)
    assert all(isinstance(part, str) for part in argv)
    # No argument may contain a shell metacharacter or an embedded space-separated
    # pair, which is how a "list" silently becomes a string.
    for part in argv[1:]:
        assert not set(part) & set(";|&`$><\n"), part


def test_every_httpx_flag_always_appears():
    """No opt-in toggle left — every collection flag runs on every scan,
    regardless of what (if anything) a caller passes."""
    parsed = opts.parse({"domains": ["example.com"], "authorised": True})
    argv = opts.httpx_argv("httpx", parsed, input_path="i", output_path="o")
    for flag in opts.HTTPX_FLAGS:
        assert flag in argv


def test_the_port_list_comes_from_the_named_profile():
    parsed = opts.parse({"domains": ["example.com"], "authorised": True,
                         "profile": "web"})
    argv = opts.httpx_argv("httpx", parsed, input_path="i", output_path="o")
    assert argv[argv.index("-ports") + 1] == "80,443"


def test_subfinder_runs_passively():
    """Brute force would send a lot of traffic to someone's DNS for a marginal
    gain, and would stop being "passive discovery"."""
    argv = opts.subfinder_argv("subfinder", "example.com")
    assert "-d" in argv and "example.com" in argv
    for forbidden in ("-b", "-brute", "-w", "-wordlist"):
        assert forbidden not in argv


def test_the_ui_catalogue_matches_what_can_actually_run():
    """The form is generated from the same tables that build argv, so it cannot
    offer an option the server would reject."""
    catalogue = opts.catalogue()
    assert set(catalogue["profiles"]) == set(opts.PORT_PROFILES)
    assert catalogue["default_profile"] in catalogue["profiles"]
    assert set(catalogue["target_kinds"]) == set(opts.TARGET_KINDS)


def test_dnsx_ptr_argv_is_a_list_with_no_asn_lookup():
    """No `-asn`/`-cdn` here — those hit dnsx's own ASN path, which this
    release deliberately does not depend on (see config/cloud_ranges.yaml)."""
    argv = opts.dnsx_ptr_argv("/usr/bin/dnsx", input_path="/tmp/ips.txt")
    assert isinstance(argv, list)
    assert all(isinstance(part, str) for part in argv)
    assert "-ptr" in argv
    assert "-asn" not in argv and "-cdn" not in argv
    for part in argv[1:]:
        assert not set(part) & set(";|&`$><\n"), part


def test_mapcidr_expand_argv_is_a_list_with_no_json_flag():
    """mapcidr has no `-json` output mode at all — passing one would be
    silently ignored at best, so it must never appear here."""
    argv = opts.mapcidr_expand_argv("/usr/bin/mapcidr", input_path="/tmp/cidrs.txt")
    assert isinstance(argv, list)
    assert "-json" not in argv and "-j" not in argv
    assert "-cl" in argv
    for part in argv[1:]:
        assert not set(part) & set(";|&`$><\n"), part


def test_naabu_argv_scans_the_same_ports_httpx_would_have():
    """naabu's job is to pre-filter what httpx would otherwise probe blindly
    — scanning a different port set would defeat that."""
    parsed = opts.parse({"domains": ["example.com"], "authorised": True,
                         "profile": "common"})
    argv = opts.naabu_argv("/usr/bin/naabu", parsed, input_path="/tmp/hosts.txt")
    assert isinstance(argv, list)
    ports = ",".join(str(p) for p in sorted(set(opts.PORT_PROFILES["common"]["ports"])))
    assert "-port" in argv
    assert argv[argv.index("-port") + 1] == ports
    # TCP connect, not raw SYN: docker-compose.yml runs with cap_drop: ["ALL"].
    assert "-scan-type" in argv
    assert argv[argv.index("-scan-type") + 1] == "c"
    for part in argv[1:]:
        assert not set(part) & set(";|&`$><\n"), part


def test_httpx_argv_omits_ports_flag_when_input_is_prescoped():
    """Confirmed against the real httpx binary: `-ports` OVERRIDES an
    embedded `host:port` in the input rather than deferring to it — passing
    both would silently throw away naabu's filtering."""
    parsed = opts.parse({"domains": ["example.com"], "authorised": True})
    scoped = opts.httpx_argv("/usr/bin/httpx", parsed, input_path="/tmp/hp.txt",
                             output_path="/tmp/out.csv", ports_prescoped=True)
    assert "-ports" not in scoped

    unscoped = opts.httpx_argv("/usr/bin/httpx", parsed, input_path="/tmp/hosts.txt",
                               output_path="/tmp/out.csv", ports_prescoped=False)
    assert "-ports" in unscoped


# ── Scale gate ──────────────────────────────────────────────────────────────

def test_a_large_enumeration_probes_without_pausing(monkeypatch, tmp_path):
    """A scan is a decision made once, at submission (the `authorised`
    checkbox) — not one asked again mid-run because enumeration turned out
    bigger than expected. `approved_hosts` defaults to the ceiling, so the
    interactive pause never fires; `MAX_HOSTS` is the only thing left that
    can still stop a scan outright, and only for a genuinely runaway estate."""
    parsed = opts.parse({"domains": ["example.com"], "authorised": True})
    run = ScanRun(parsed, workdir=tmp_path)

    hosts = [f"h{n}.example.com" for n in range(opts.CONFIRM_ABOVE + 1)]
    monkeypatch.setattr(run, "_enumerate", lambda: hosts)
    monkeypatch.setattr(tools, "missing", lambda: [])
    # Real naabu shouldn't run against 500 fake hostnames just to reach the
    # mocked `_probe` below — `_port_scan` degrades to its no-naabu fallback.
    monkeypatch.setattr(tools, "find", lambda name: "" if name == "naabu" else "")
    probed: list = []

    def fake_probe(hosts_file, csv_file, **kwargs):
        probed.append(hosts_file)
        csv_file.write_text("host,port\nexample.com,443\n", encoding="utf-8")

    monkeypatch.setattr(run, "_probe", fake_probe)
    run.run()
    assert probed, "a large enumeration should probe without being asked"


def test_an_approved_count_lets_the_scan_proceed(monkeypatch, tmp_path):
    hosts = [f"h{n}.example.com" for n in range(opts.CONFIRM_ABOVE + 1)]
    parsed = opts.parse({"domains": ["example.com"], "authorised": True,
                         "approved_hosts": len(hosts)})
    run = ScanRun(parsed, workdir=tmp_path)

    monkeypatch.setattr(run, "_enumerate", lambda: hosts)
    monkeypatch.setattr(tools, "missing", lambda: [])
    monkeypatch.setattr(tools, "find", lambda name: "")
    probed: list = []

    def fake_probe(hosts_file, csv_file, **kwargs):
        probed.append(hosts_file)
        csv_file.write_text("host,port\nexample.com,443\n", encoding="utf-8")

    monkeypatch.setattr(run, "_probe", fake_probe)
    run.run()
    assert probed, "an approved scan should proceed"


def test_a_small_scan_needs_no_approval(monkeypatch, tmp_path):
    """The gate is about scale. Asking twice for three hosts is friction, not
    safety."""
    parsed = opts.parse({"domains": ["example.com"], "authorised": True})
    run = ScanRun(parsed, workdir=tmp_path)
    monkeypatch.setattr(run, "_enumerate", lambda: ["a.example.com"])
    monkeypatch.setattr(tools, "missing", lambda: [])
    monkeypatch.setattr(tools, "find", lambda name: "")
    monkeypatch.setattr(run, "_probe",
                        lambda hosts_file, csv_file, **kwargs:
                        csv_file.write_text("host\na.example.com\n",
                                            encoding="utf-8"))
    run.run()


def test_the_hard_ceiling_still_exists_below_the_old_gate_threshold():
    """Manual scans no longer pause at `CONFIRM_ABOVE` to ask — `approved_hosts`
    defaults to `MAX_HOSTS` (see `options.parse`). `CONFIRM_ABOVE` and
    `NeedsApproval` remain, since the scheduler still uses them: it pre-sets
    `approved_hosts` to each schedule's own cap and relies on `NeedsApproval`
    firing (and the run being skipped, not force-continued) when a run would
    exceed that cap — see `scan/scheduler.py`."""
    assert opts.CONFIRM_ABOVE <= opts.MAX_HOSTS


# ── Missing tools ───────────────────────────────────────────────────────────

def test_a_missing_scanner_is_explained_not_crashed(monkeypatch, tmp_path):
    parsed = opts.parse({"domains": ["example.com"], "authorised": True})
    run = ScanRun(parsed, workdir=tmp_path)
    monkeypatch.setattr(tools, "missing", lambda: ["httpx"])

    from frogscope.scan.runner import ScanError
    with pytest.raises(ScanError) as caught:
        run.run()
    message = str(caught.value)
    assert "httpx" in message
    assert "Docker" in message or "go install" in message


def test_tool_inventory_never_raises_when_nothing_is_installed(monkeypatch):
    monkeypatch.setattr(tools, "find", lambda name: "")
    found = tools.inventory()
    assert set(found) == {"subfinder", "httpx", "dnsx", "mapcidr", "tlsx", "naabu"}
    for tool in found.values():
        assert tool.available is False
        assert tool.install_hint


# ── Empty results are not errors ─────────────────────────────────────────────
#
# A domain with no live subdomains, or a target list nothing answers on, is a
# legitimate outcome — not a failure of the tool. `EmptyResult` (distinct
# from `ScanError`) is what lets the UI (scan.js's `ScanOutcome`) say so
# calmly instead of showing the same red "scan failed" a missing tool or a
# crashed subprocess gets.

def test_a_domain_with_nothing_resolved_is_an_empty_result_not_an_error(monkeypatch, tmp_path):
    from frogscope.scan.runner import EmptyResult

    parsed = opts.parse({"domains": ["example.com"], "authorised": True})
    run = ScanRun(parsed, workdir=tmp_path)
    monkeypatch.setattr(tools, "missing", lambda: [])
    monkeypatch.setattr(run, "_resolve_targets", lambda directory: [])

    with pytest.raises(EmptyResult) as caught:
        run.run()
    assert "example.com" in str(caught.value)


def test_an_unresolvable_ip_or_cidr_target_is_also_an_empty_result(monkeypatch, tmp_path):
    from frogscope.scan.runner import EmptyResult

    parsed = opts.parse({"targets": ["203.0.113.5"], "authorised": True})
    run = ScanRun(parsed, workdir=tmp_path)
    monkeypatch.setattr(tools, "missing", lambda: [])
    monkeypatch.setattr(run, "_resolve_targets", lambda directory: [])

    with pytest.raises(EmptyResult) as caught:
        run.run()
    assert "resolved to nothing" in str(caught.value)


def test_httpx_probing_nothing_live_is_an_empty_result_not_an_error(monkeypatch, tmp_path):
    from frogscope.scan.runner import EmptyResult

    parsed = opts.parse({"domains": ["example.com"], "authorised": True})
    run = ScanRun(parsed, workdir=tmp_path)
    monkeypatch.setattr(tools, "missing", lambda: [])
    monkeypatch.setattr(run, "_resolve_targets", lambda directory: ["a.example.com"])
    monkeypatch.setattr(run, "_port_scan", lambda directory, hosts: None)
    # Leaves `csv_file` unwritten — httpx exited cleanly but nothing answered.
    monkeypatch.setattr(run, "_probe", lambda hosts_file, csv_file, **kwargs: None)

    with pytest.raises(EmptyResult) as caught:
        run.run()
    assert "none answered" in str(caught.value)


def test_missing_defaults_to_core_tools_only(monkeypatch):
    """A machine without dnsx/mapcidr/tlsx must still be able to run a plain
    domain scan — EXTRA tools power DNS/network analysis, TLS certificate
    reading, and IP/CIDR target resolution, all unconditional now but
    degrading gracefully (a skip_reason on their own sidecar collector)
    rather than blocking the base scan when absent."""
    monkeypatch.setattr(tools, "find",
                        lambda name: "" if name in tools.EXTRA else f"/bin/{name}")
    assert tools.missing() == []
    assert set(tools.missing(required=tools.ALL)) == set(tools.EXTRA)


# ── Port scanning (naabu) ────────────────────────────────────────────────────

def test_port_scan_falls_back_when_naabu_is_absent(monkeypatch, tmp_path):
    """`None`, not an empty list — the caller's signal to probe `hosts`
    directly across the whole port profile, exactly like before naabu
    existed, rather than writing an empty (and wrong) host:port file."""
    parsed = opts.parse({"domains": ["example.com"], "authorised": True})
    run = ScanRun(parsed, workdir=tmp_path)
    monkeypatch.setattr(tools, "find", lambda name: "")
    assert run._port_scan(tmp_path, ["a.example.com"]) is None


def test_port_scan_returns_open_host_port_pairs(monkeypatch, tmp_path):
    """Real naabu -json shape, confirmed against the installed binary:
    one line per OPEN port, `{"host","ip","port",...}`."""
    parsed = opts.parse({"domains": ["example.com"], "authorised": True})
    run = ScanRun(parsed, workdir=tmp_path)
    monkeypatch.setattr(tools, "find", lambda name: f"/usr/bin/{name}")

    def fake_stream(argv):
        yield '{"host":"a.example.com","ip":"1.2.3.4","port":443,"protocol":"tcp","tls":false}\n'
        yield '{"host":"a.example.com","ip":"1.2.3.4","port":80,"protocol":"tcp","tls":false}\n'

    monkeypatch.setattr(run, "_stream", fake_stream)
    pairs = run._port_scan(tmp_path, ["a.example.com"])
    assert pairs == ["a.example.com:443", "a.example.com:80"] \
        or pairs == ["a.example.com:80", "a.example.com:443"]
    assert set(pairs) == {"a.example.com:443", "a.example.com:80"}


def test_https_targets_from_csv_filters_by_scheme(tmp_path):
    """`tlsx` should only read certs from what httpx actually found live over
    HTTPS — not http-only rows, not rows for hosts nothing answered on."""
    csv_file = tmp_path / "scan.csv"
    csv_file.write_text(
        "host,port,scheme\n"
        "a.example.com,443,https\n"
        "b.example.com,80,http\n"
        "a.example.com,8443,https\n",
        encoding="utf-8")
    assert set(_https_targets_from_csv(csv_file)) == {
        "a.example.com:443", "a.example.com:8443"}


def test_https_targets_from_csv_handles_a_missing_file(tmp_path):
    assert _https_targets_from_csv(tmp_path / "does_not_exist.csv") == []


def test_correlate_dns_resolve_uses_full_hosts_not_tls_filtered(monkeypatch, tmp_path):
    """dnsx's domain-resolve step must see every originally-targeted host,
    regardless of which subset turned out to serve HTTPS — dangling-record/
    PTR-mismatch findings specifically need DNS data for hosts that answer
    on nothing at all, so this must never get narrowed to match
    `tls_targets`. A regression guard for that explicit design decision."""
    parsed = opts.parse({"domains": ["a.example.com", "b.example.com"],
                         "authorised": True})
    run = ScanRun(parsed, workdir=tmp_path)
    monkeypatch.setattr(tools, "find", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(run, "_stream", lambda argv: iter(()))

    hosts = ["a.example.com", "b.example.com"]
    tls_targets = ["a.example.com:443"]  # much narrower — only one host
    run._correlate(tmp_path, hosts, tls_targets, tmp_path / "correlation.json")

    domains_file = tmp_path / "correlate_domains.txt"
    assert domains_file.exists()
    assert set(domains_file.read_text(encoding="utf-8").split()) == set(hosts)


# ── No shell, anywhere ──────────────────────────────────────────────────────

def test_no_subprocess_is_started_through_a_shell():
    """`shell=True` anywhere in this package would make the domain pattern the only
    thing standing between a text box and a command."""
    for path in Path("frogscope/scan").glob("*.py"):
        source = path.read_text(encoding="utf-8")
        assert "shell=True" not in source, path
        assert "os.system" not in source, path
        assert "os.popen" not in source, path


def test_the_scan_package_is_the_only_place_that_spawns_a_scanner():
    """Keeping it in one package is what makes the network behaviour reviewable."""
    for path in Path("frogscope").rglob("*.py"):
        if path.parts[1] in ("scan", "verify"):
            continue
        source = path.read_text(encoding="utf-8")
        assert "subprocess.Popen" not in source, path


# ── Identity: hostname, never the resolved address (regression) ──────────────

def test_a_hostname_beats_the_resolved_address():
    """httpx's `host` column holds the RESOLVED ADDRESS and `input` the name it
    probed. Trusting `host` keyed every endpoint on an IP, so identity rotated with
    round-robin DNS and every scan reported the whole estate as new."""
    from frogscope.ingest.loader import _host_from

    assert _host_from({"url": "https://example.org:443",
                       "input": "example.org",
                       "host": "104.20.26.136"}).startswith("example.org")
    assert _host_from({"input": "example.org",
                       "host": "104.20.26.136"}) == "example.org"


def test_a_csv_whose_host_column_is_a_hostname_still_works():
    """Some httpx versions and exports put the name in `host`. Both shapes have to
    load, so the fix cannot simply swap which column is trusted."""
    from frogscope.ingest.loader import _host_from

    assert _host_from({"host": "adm.example.com"}) == "adm.example.com"


def test_an_endpoint_probed_by_address_is_kept_not_dropped():
    """A host with no name is still a real endpoint."""
    from frogscope.ingest.loader import _host_from

    assert _host_from({"url": "https://198.51.100.7:443",
                       "input": "198.51.100.7",
                       "host": "198.51.100.7"}).startswith("198.51.100.7")


def test_an_address_has_no_registrable_domain():
    """Splitting 104.20.21.8 on dots produced the nonsense domain "21.8", which then
    grouped unrelated hosts together in every by-zone breakdown."""
    from frogscope.ingest.normalize import is_address, registrable_domain, zone_of

    assert is_address("104.20.21.8")
    assert is_address("2606:4700::1")
    assert not is_address("a.b.example.com")

    assert registrable_domain("104.20.21.8", ["co.uk"]) == "104.20.21.8"
    assert zone_of("104.20.21.8", "example.com") == "ip-address"


def test_an_apex_domain_is_its_own_zone_not_the_public_suffix():
    """Dropping the leftmost label of a two-label name leaves the suffix, so
    example.com landed in the zone "com" — grouping every unrelated .com host."""
    from frogscope.ingest.normalize import zone_of

    assert zone_of("example.com", "example.com") == "direct"
    assert zone_of("www.example.com", "example.com") == "direct"
    assert zone_of("a.b.example.com", "example.com") == "b.example.com"


def test_the_answering_address_survives_the_identity_change():
    """Concentration and shared-infrastructure findings need the resolved address.
    Taking the hostname from `input` must not throw the address away."""
    import csv
    import pathlib
    import tempfile

    from frogscope.config import load_config
    from frogscope.ingest import pipeline

    cfg = load_config()
    directory = pathlib.Path(tempfile.mkdtemp())
    path = directory / "scan.csv"
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=[
            "timestamp", "port", "url", "input", "host", "title", "scheme",
            "status_code", "a"])
        writer.writeheader()
        writer.writerow({
            "timestamp": "2026-03-02T09:00:00.000000+00:00",
            "port": 443, "url": "https://example.org:443",
            "input": "example.org", "host": "104.20.26.136",
            "title": "Example", "scheme": "https", "status_code": 200,
            "a": '["104.20.26.136"]',
        })

    records, _rollups, _load, _collapse, _entities = pipeline.analyse(path, cfg)
    record = records[0]
    assert record["host"] == "example.org", "identity must be the name"
    assert record["host_ip"] == "104.20.26.136", "the address must be kept"


# ── Multiple primary domains ────────────────────────────────────────────────

def test_several_primary_domains_are_accepted():
    """A large organisation has more than one: a main brand, country domains, an
    acquisition. A tool that takes only one leaves part of the estate unwatched."""
    parsed = opts.parse({
        "domains": "acme.com\nacme.co.uk\nacmegroup.com",
        "authorised": True,
    })
    assert parsed.domains == ["acme.com", "acme.co.uk", "acmegroup.com"]


def test_every_domain_is_enumerated_and_merged_into_one_probe(monkeypatch,
                                                              tmp_path):
    """Subdomains of all of them go into a single host list, so the project holds
    the whole estate as one run rather than one run per domain."""
    parsed = opts.parse({"domains": "a.example.com\nb.example.net",
                         "authorised": True})
    run = ScanRun(parsed, workdir=tmp_path)
    monkeypatch.setattr(tools, "missing", lambda: [])
    # naabu "not found": this test asserts on the plain merged host list
    # reaching `_probe`, not on port-scan filtering — `_port_scan` degrades
    # to its no-naabu fallback so `hosts_file` still holds bare hostnames.
    monkeypatch.setattr(tools, "find",
                        lambda name: "" if name == "naabu" else f"/usr/bin/{name}")

    asked: list[str] = []

    def fake_stream(argv):
        if "-d" not in argv:
            # DNS/network analysis now always runs after probing (not just
            # subfinder enumeration) — nothing for this test to assert on,
            # so it yields nothing rather than needing a `-d`-shaped argv.
            return
        domain = argv[argv.index("-d") + 1]
        asked.append(domain)
        yield f"www.{domain}\n"
        yield f"api.{domain}\n"

    monkeypatch.setattr(run, "_stream", fake_stream)
    probed: dict = {}

    def fake_probe(hosts_file, csv_file, **kwargs):
        probed["hosts"] = hosts_file.read_text(encoding="utf-8").split()
        csv_file.write_text("host\nx\n", encoding="utf-8")

    monkeypatch.setattr(run, "_probe", fake_probe)
    run.run()

    assert asked == ["a.example.com", "b.example.net"]
    # Both domains' subdomains, plus each domain itself, in one list.
    assert set(probed["hosts"]) == {
        "a.example.com", "www.a.example.com", "api.a.example.com",
        "b.example.net", "www.b.example.net", "api.b.example.net",
    }


# ── The manual guide is generated, not written out ───────────────────────────

def test_the_manual_commands_come_from_the_same_tables_the_scanner_uses():
    """A hand-written guide drifts. A copied command missing `-body-preview`
    silently disables a set of checks, and the user would never know why their
    findings differ from a scan run in the UI."""
    steps = opts.manual_commands()
    httpx_step = next(s for s in steps if "httpx" in s["command"])

    parsed = opts.ScanOptions(domains=["example.com"], profile=opts.DEFAULT_PROFILE)
    expected = opts.httpx_argv("httpx", parsed, input_path="hosts.txt",
                               output_path="scan.csv")
    assert httpx_step["command"] == " ".join(expected)


def test_the_guide_enables_every_collection_flag():
    """Otherwise the manual route produces a CSV that unlocks fewer checks than the
    built-in scanner would."""
    steps = opts.manual_commands()
    command = next(s["command"] for s in steps if "httpx" in s["command"])
    for flag in opts.HTTPX_FLAGS:
        assert flag in command


def test_the_guide_starts_with_subdomain_discovery():
    steps = opts.manual_commands()
    assert "subfinder" in steps[0]["command"]
    assert "-o hosts.txt" in steps[0]["command"]


def test_the_catalogue_exposes_the_guide_to_the_ui():
    assert opts.catalogue()["manual"] == opts.manual_commands()


# ── Concurrent enumeration ───────────────────────────────────────────────────

def test_enumeration_runs_domains_concurrently(monkeypatch, tmp_path):
    """subfinder takes ~30s per domain. Sequentially, a 400-domain portfolio is
    three hours during which the UI looks hung."""
    domains = [f"d{n}.example.com" for n in range(24)]
    parsed = opts.parse({"domains": domains, "authorised": True})
    run = ScanRun(parsed, workdir=tmp_path)
    monkeypatch.setattr(tools, "find", lambda name: f"/usr/bin/{name}")

    import threading
    concurrent = 0
    peak = 0
    lock = threading.Lock()

    def fake_stream(argv):
        nonlocal concurrent, peak
        domain = argv[argv.index("-d") + 1]
        with lock:
            concurrent += 1
            peak = max(peak, concurrent)
        import time
        time.sleep(0.05)
        with lock:
            concurrent -= 1
        yield f"www.{domain}\n"

    monkeypatch.setattr(run, "_stream", fake_stream)
    hosts = run._enumerate()

    assert peak > 1, "enumeration ran one domain at a time"
    assert peak <= opts.ENUMERATION_WORKERS
    assert len(hosts) == len(domains) * 2   # each domain plus its www


def test_every_domain_and_its_subdomains_end_up_in_one_list(monkeypatch, tmp_path):
    parsed = opts.parse({"domains": "a.example.com\nb.example.net",
                         "authorised": True})
    run = ScanRun(parsed, workdir=tmp_path)
    monkeypatch.setattr(tools, "find", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(run, "_stream", lambda argv: iter(
        [f"www.{argv[argv.index('-d') + 1]}\n"]))

    assert set(run._enumerate()) == {
        "a.example.com", "www.a.example.com",
        "b.example.net", "www.b.example.net",
    }


def test_one_failing_domain_does_not_lose_the_others(monkeypatch, tmp_path):
    """A portfolio of hundreds will contain a few that error. Discarding every other
    result for one of them would be absurd."""
    from frogscope.scan.runner import ScanError

    parsed = opts.parse({"domains": "good.example.com\nbad.example.com",
                         "authorised": True})
    run = ScanRun(parsed, workdir=tmp_path)
    monkeypatch.setattr(tools, "find", lambda name: f"/usr/bin/{name}")

    def fake_stream(argv):
        domain = argv[argv.index("-d") + 1]
        if domain.startswith("bad"):
            raise ScanError("subfinder exited 1")
        yield f"www.{domain}\n"

    monkeypatch.setattr(run, "_stream", fake_stream)
    hosts = run._enumerate()
    assert "www.good.example.com" in hosts


def test_cancelling_stops_every_worker_not_just_one():
    """A single-process field would leave every worker but the last one running."""
    source = Path("frogscope/scan/runner.py").read_text(encoding="utf-8")
    assert "self._processes: set[subprocess.Popen]" in source
    assert "for process in running:" in source
    assert "self._process:" not in source, "the single-slot field is back"
