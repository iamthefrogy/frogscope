"""Offline export, verification, and watch-folder tests."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from frogscope.config import load_config
from frogscope.db.connection import connect
from frogscope.db.migrate import migrate
from frogscope.export import snapshot
from frogscope.export.redact import Redactor
from frogscope.ingest import pipeline
from frogscope.scoring.rules import load_ruleset
from frogscope.verify import takeover as verify_mod

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
    conn = connect(tmp_path / "snap.sqlite")
    migrate(conn)
    result = pipeline.ingest(conn, cfg, FIXTURE, project="s", label="r1",
                             allow_incomplete=True, keep_raw=False)
    run = conn.execute("SELECT * FROM runs WHERE id = ?",
                       (result.run_id,)).fetchone()
    yield conn, run, result
    conn.close()


# ── Columnar encoding ───────────────────────────────────────────────────────

def test_encode_decode_round_trip():
    rows = [
        {"a": 1, "b": "x", "c": [1, 2]},
        {"a": 2, "b": "x", "c": [1, 2]},
        {"a": 3, "b": "y", "c": None},
    ]
    table = snapshot.encode_table(rows)
    assert table["n"] == 3
    # Rebuild the way the shim does.
    out = []
    for index in range(table["n"]):
        row = {}
        for name, column in table["columns"].items():
            raw = column[index]
            row[name] = (table["dicts"][name][raw] if name in table["dicts"]
                         else raw)
        out.append(row)
    assert out == rows


def test_repeated_values_are_dictionary_encoded():
    """The whole point: most columns are low-cardinality enums repeated once per
    row, and as plain objects they were 2.4 MB for a modest estate."""
    rows = [{"env": "prod", "n": i} for i in range(500)]
    table = snapshot.encode_table(rows)
    assert "env" in table["dicts"]
    assert table["dicts"]["env"] == ["prod"]
    # A unique column is not worth an indirection.
    assert "n" not in table["dicts"]


def test_encode_handles_no_rows():
    assert snapshot.encode_table([])["n"] == 0


# ── Payload ─────────────────────────────────────────────────────────────────

def test_payload_covers_every_view(db, cfg, ruleset):
    conn, run, _result = db
    payload = snapshot.build_payload(conn, cfg, run, ruleset)
    for key in ("columns", "endpoints", "endpoint_detail", "scores", "hosts",
                "findings", "rules", "risk", "exec", "summary", "quality",
                "changes", "trends", "inventory", "presence", "history"):
        assert key in payload, key
    for kind in ("technology", "infrastructure", "auth", "takeover"):
        assert kind in payload["inventory"]


def test_drawer_detail_does_not_duplicate_columnar_columns(db, cfg, ruleset):
    """Duplicating every scalar column cost 5.9 MB, over a third of the file, for
    data the grid already holds."""
    from frogscope.query.catalog import Catalog

    conn, run, _result = db
    payload = snapshot.build_payload(conn, cfg, run, ruleset)
    columnar = set(Catalog(cfg).order)
    for detail in list(payload["endpoint_detail"].values())[:20]:
        assert not (set(detail) & columnar), (
            "detail must hold only what the columnar table lacks")


def test_score_traces_are_pooled(db, cfg, ruleset):
    """One rule fires on hundreds of endpoints with identical `why` and
    `remediation` text; storing each copy cost another 5.5 MB."""
    conn, run, _result = db
    payload = snapshot.build_payload(conn, cfg, run, ruleset)
    assert payload["score_pool"], "expected an interned pool"
    for record in list(payload["scores"].values())[:20]:
        for entry in record.get("contributions") or []:
            assert isinstance(entry, int), "contributions must be pool indices"
            assert entry < len(payload["score_pool"])


def test_raw_source_blob_is_omitted(db, cfg, ruleset):
    conn, run, _result = db
    payload = snapshot.build_payload(conn, cfg, run, ruleset)
    for detail in payload["endpoint_detail"].values():
        assert "raw_json" not in detail
        assert "raw" not in detail


def test_findings_flat_array_is_not_duplicated(db, cfg, ruleset):
    """The flat array and the grouped form are the same records; carrying both
    cost over a megabyte."""
    conn, run, _result = db
    payload = snapshot.build_payload(conn, cfg, run, ruleset)
    assert "grouped" in payload["findings"]
    assert "findings" not in payload["findings"]


# ── HTML ────────────────────────────────────────────────────────────────────

def test_html_has_no_external_references(db, cfg, ruleset):
    """The file must open with networking disabled, so a single CDN or font
    request breaks the whole feature."""
    conn, run, _result = db
    html = snapshot.build_html(conn, cfg, run, ruleset)

    for pattern in (r'src="https?://', r'href="https?://',
                    r"@import\s+url\(https?://", r"url\(https?://"):
        assert not re.search(pattern, html), pattern
    assert "fonts.googleapis" not in html
    assert "cdn.jsdelivr" not in html
    assert "unpkg.com" not in html


def test_html_inlines_every_module_exactly_once(db, cfg, ruleset):
    """Rewriting relative imports to dependency data: URLs duplicated shared
    modules once per importer and took the file from 5 MB to 9 MB. An import map
    means each module's text appears once."""
    conn, run, _result = db
    html = snapshot.build_html(conn, cfg, run, ruleset)

    match = re.search(r'<script type="importmap">(.*?)</script>', html, re.S)
    assert match, "expected an import map"
    imports = json.loads(match.group(1))["imports"]
    for name in ("preact", "preact/hooks", "htm", "frogscope/main",
                 "frogscope/lib", "frogscope/views"):
        assert name in imports, name
    urls = list(imports.values())
    assert len(urls) == len(set(urls)), "each module must appear once"


def test_no_module_is_concatenated_into_one_scope(db, cfg, ruleset):
    """Every view file declares `const html = htm.bind(h)`, so a single scope is
    an immediate redeclaration error."""
    conn, run, _result = db
    html = snapshot.build_html(conn, cfg, run, ruleset)
    # The entry point is referenced, not inlined as a bare module body.
    assert re.search(r'<script type="module" src="data:', html)


def test_payload_is_valid_json_and_script_safe(db, cfg, ruleset):
    conn, run, _result = db
    html = snapshot.build_html(conn, cfg, run, ruleset)
    match = re.search(
        r'<script id="frogscope-payload" type="application/json">(.*?)</script>',
        html, re.S)
    assert match
    body = match.group(1)
    # An unescaped "</" inside the JSON would terminate the script element early.
    assert "</" not in body
    json.loads(body.replace("<\\/", "</"))


def test_html_states_what_offline_cannot_do(db, cfg, ruleset):
    conn, run, _result = db
    html = snapshot.build_html(conn, cfg, run, ruleset)
    assert "Offline export" in html
    assert "live application" in html


# ── Redaction of the whole payload ──────────────────────────────────────────

def test_redacted_snapshot_leaks_nothing(db, cfg, ruleset):
    """Several payload sections are keyed BY endpoint, so redacting only values
    left 8,000-plus hostnames sitting in the dictionary keys."""
    conn, run, _result = db
    html = snapshot.build_html(conn, cfg, run, ruleset,
                              redactor=Redactor(salt="fixed"))
    assert "example.com" not in html.replace("org-", "|").replace(
        ".example", "|"), "real fixture domain must not survive"
    assert "203.0.113." not in html
    assert re.search(r"org-[0-9a-f]{6}\.example", html)


def test_redaction_covers_dictionary_keys():
    redactor = Redactor(salt="fixed")
    redactor.host("a.b.acme-corp.com")
    out = redactor.text({"a.b.acme-corp.com:443": {"x": 1}})
    assert "acme-corp" not in json.dumps(out)


def test_redacted_snapshot_still_parses(db, cfg, ruleset):
    conn, run, _result = db
    html = snapshot.build_html(conn, cfg, run, ruleset, redactor=Redactor())
    match = re.search(
        r'<script id="frogscope-payload" type="application/json">(.*?)</script>',
        html, re.S)
    payload = json.loads(match.group(1).replace("<\\/", "</"))
    assert payload["endpoints"]["n"] > 0


def test_snapshot_write_returns_a_size(tmp_path, db, cfg, ruleset):
    conn, run, _result = db
    out = tmp_path / "r.html"
    size = snapshot.write(out, conn, cfg, run, ruleset)
    assert size == len(out.read_bytes())
    assert size > 10_000


# ── Verification: judgement logic, no network ───────────────────────────────

CFG_TAKEOVER = {
    "grades": {"high": {"label": "Likely dangling", "confidence": "probable"}},
    "providers": [{
        "provider": "Azure App Service",
        "cname_suffixes": ["azurewebsites.net"],
        "body_fingerprints": ["Error 404 - Web app not found"],
        "title_fingerprints": ["Web App - Unavailable"],
        "claimable": True,
    }],
}


def _observe(**kw) -> verify_mod.Observation:
    observation = verify_mod.Observation(host="x.example.com")
    for key, value in kw.items():
        setattr(observation, key, value)
    return observation


def test_confirmed_requires_the_provider_fingerprint():
    candidate = {"host": "x.example.com", "provider": "Azure App Service"}
    observation = _observe(resolved=True, http_status=404,
                           body_sample="<h1>Web App - Unavailable</h1>")
    verify_mod._judge(candidate, observation, CFG_TAKEOVER)
    assert observation.verdict == "confirmed"
    assert "fingerprint" in observation.reason


def test_a_missing_cname_target_is_likely_not_confirmed():
    """A dangling record nobody has claimed yet looks much like a healthy one
    from outside, so this stays short of confirmed."""
    candidate = {"host": "x.example.com", "provider": "Azure App Service"}
    observation = _observe(resolved=True, cname_resolves=False,
                           cname_target="gone.azurewebsites.net",
                           http_status=404, body_sample="nothing here")
    verify_mod._judge(candidate, observation, CFG_TAKEOVER)
    assert observation.verdict == "likely"


def test_a_serving_host_is_reported_as_a_false_positive():
    candidate = {"host": "x.example.com", "provider": "Azure App Service"}
    observation = _observe(resolved=True, http_status=200,
                           body_sample="<h1>My application</h1>")
    verify_mod._judge(candidate, observation, CFG_TAKEOVER)
    assert observation.verdict == "not_dangling"
    assert "false positive" in observation.reason


def test_dns_only_says_the_fingerprint_was_never_checked():
    """Reporting a bare "unconfirmed" would imply the check ran and found
    nothing. A Cloudflare 530 is only visible in an HTTP response."""
    candidate = {"host": "x.example.com", "provider": "Cloudflare"}
    observation = _observe(resolved=True, cname_resolves=True,
                           cname_target="x.example.com.cdn.cloudflare.net")
    verify_mod._judge(candidate, observation, CFG_TAKEOVER, http_checked=False)
    assert observation.verdict == "unconfirmed"
    assert "--dns-only" in observation.reason
    assert "never checked" in observation.reason


def test_dns_only_cannot_declare_a_host_healthy():
    candidate = {"host": "x.example.com", "provider": "Cloudflare"}
    observation = _observe(resolved=True, http_status=200)
    verify_mod._judge(candidate, observation, CFG_TAKEOVER, http_checked=False)
    assert observation.verdict != "not_dangling"


def test_an_unresolvable_host_is_a_stale_record():
    candidate = {"host": "x.example.com", "provider": "Azure App Service"}
    observation = _observe(resolved=False)
    verify_mod._judge(candidate, observation, CFG_TAKEOVER)
    assert observation.verdict == "stale_record"


def test_verification_never_writes_over_the_scan_grade(db, cfg, ruleset):
    """The scan said what it could see; verification is a later, independent
    observation. Merging them would lose the distinction."""
    conn, run, _result = db
    verify_mod.persist(conn, run["id"], {"checked": 0, "results": []})
    row = conn.execute("SELECT verify_json, id FROM runs WHERE id = ?",
                       (run["id"],)).fetchone()
    assert json.loads(row["verify_json"])["checked"] == 0
    # takeover_grade on endpoints is untouched by verification.
    columns = {r["name"] for r in conn.execute("PRAGMA table_info(endpoints)")}
    assert "takeover_grade" in columns


def test_verify_module_makes_no_request_at_import_time():
    """A module that reaches the network on import cannot be safely imported by
    anything that is not about to verify."""
    import pathlib
    source = pathlib.Path(verify_mod.__file__).read_text(encoding="utf-8")
    top_level = [
        line for line in source.splitlines()
        if line and not line.startswith((" ", "\t", "#", '"', "'"))
    ]
    for line in top_level:
        assert "urlopen" not in line
        assert "getaddrinfo" not in line


# ── Watch folder ────────────────────────────────────────────────────────────

def test_watch_records_what_it_did(tmp_path, cfg, monkeypatch):
    """The ledger is what stops a restart re-ingesting everything already sitting
    in the folder."""
    import shutil

    monkeypatch.setattr(cfg, "data_dir", tmp_path)
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    shutil.copy(FIXTURE, inbox / "scan.csv")

    conn = connect(tmp_path / "w.sqlite")
    migrate(conn)
    columns = {r["name"] for r in conn.execute("PRAGMA table_info(watched_files)")}
    assert {"path", "sha256", "outcome", "seen_at"} <= columns
    conn.close()


def test_watch_settle_check_rejects_a_growing_file(tmp_path):
    """A file still being copied in would ingest as a truncated scan, which then
    reads as an improvement it did not earn."""
    from frogscope.cli import _is_settled

    path = tmp_path / "growing.csv"
    path.write_bytes(b"a" * 100)
    assert _is_settled(path, checks=2, gap=0.01) is True


def test_file_digest_is_stable(tmp_path):
    from frogscope.cli import _file_digest

    path = tmp_path / "f.csv"
    path.write_bytes(b"hello")
    first = _file_digest(path)
    assert first == _file_digest(path)
    path.write_bytes(b"different")
    assert _file_digest(path) != first
