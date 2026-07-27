"""Notification hooks: what gets alerted, and what must never leak."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from frogscope.config import load_config
from frogscope.db.connection import connect
from frogscope.db.migrate import migrate
from frogscope.ingest import pipeline
from frogscope.notify import alerts as A
from frogscope.notify import sinks

FIXTURE = Path(__file__).parent / "fixtures" / "sample.csv"


@pytest.fixture(scope="module")
def cfg():
    return load_config()


@pytest.fixture()
def db(tmp_path, cfg, monkeypatch):
    monkeypatch.setattr(cfg, "data_dir", tmp_path)
    conn = connect(tmp_path / "n.sqlite")
    migrate(conn)
    yield conn
    conn.close()


def _ingest(conn, cfg, label, path=FIXTURE):
    return pipeline.ingest(conn, cfg, path, project="n", label=label,
                           allow_incomplete=True, allow_drift=True,
                           keep_raw=False)


def _run(conn, run_id):
    return conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()


@pytest.fixture()
def two_runs(db, cfg, tmp_path):
    """A baseline plus a second run with a real change in it.

    The mutation strips `cdn_name`, so Cloudflare-fronted endpoints come back
    unprotected — the canonical "worsened" case. It has to be a raw httpx column:
    editing a derived value like `response_class` leaves the source bytes
    untouched, the content hash identical, and the ingest rejected as a duplicate.
    """
    import csv

    first = _ingest(db, cfg, "r1")

    with FIXTURE.open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        fields = reader.fieldnames
        rows = list(reader)
    for row in rows:
        if row.get("cdn_name") == "cloudflare":
            row["cdn_name"] = ""
            row["cdn_type"] = ""
            row["cdn"] = "false"

    second_path = tmp_path / "second.csv"
    with second_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

    second = _ingest(db, cfg, "r2", second_path)
    return _run(db, first.run_id), _run(db, second.run_id)


CFG = {
    "enabled": True,
    "triggers": {
        "new_findings": {"enabled": True, "min_severity": "high",
                         "max_listed": 5},
        "worsened": {"enabled": True, "min_score_delta": 15, "max_listed": 5},
        "takeover": {"enabled": True, "min_grade": "medium", "max_listed": 5},
        "posture_drop": {"enabled": True, "min_points": 3},
        "data_quality": {"enabled": True},
    },
    "targets": [],
    "delivery": {"timeout": 1, "retries": 0, "retry_delay": 0},
}


# ── Config ──────────────────────────────────────────────────────────────────

def test_env_vars_are_expanded(monkeypatch, tmp_path):
    monkeypatch.setenv("WS_TEST_HOOK", "https://hooks.example/abc")
    path = tmp_path / "notify.yaml"
    path.write_text("targets:\n  - name: s\n    url: ${WS_TEST_HOOK}\n")
    loaded = A.load_notify_config(tmp_path)
    assert loaded["targets"][0]["url"] == "https://hooks.example/abc"


def test_an_unset_variable_does_not_become_a_literal_url(tmp_path, monkeypatch):
    """A half-expanded URL would POST the inventory somewhere unintended."""
    monkeypatch.delenv("WS_MISSING_HOOK", raising=False)
    path = tmp_path / "notify.yaml"
    path.write_text("targets:\n  - name: s\n    kind: slack\n    enabled: true\n"
                    "    url: ${WS_MISSING_HOOK}\n")
    loaded = A.load_notify_config(tmp_path)
    usable, skipped = A.active_targets(loaded)
    assert usable == []
    assert any("unset" in s for s in skipped)


def test_a_missing_notify_config_disables_notifications(tmp_path):
    loaded = A.load_notify_config(tmp_path / "nope")
    assert loaded["enabled"] is False


def test_the_shipped_config_is_off_by_default(cfg):
    """Two locks: config `enabled` and `--send`. Neither alone posts anything."""
    loaded = A.load_notify_config(cfg.config_dir)
    assert loaded["enabled"] is False
    for target in loaded["targets"]:
        if target.get("kind") in ("slack", "webhook"):
            assert not target.get("enabled"), \
                "no remote target ships enabled"


def test_notify_config_is_not_part_of_the_config_hash(cfg, tmp_path):
    """Editing where an alert goes must not make every stored run look as though
    its scoring inputs moved — that warning has to stay meaningful."""
    import shutil

    copy = tmp_path / "cfg"
    shutil.copytree(cfg.config_dir, copy)
    before = load_config(copy, tmp_path).config_hash
    (copy / "notify.yaml").write_text("enabled: true\ntargets: []\n")
    assert load_config(copy, tmp_path).config_hash == before


def test_a_disabled_trigger_produces_nothing(db, cfg, two_runs):
    _first, second = two_runs
    quiet = {**CFG, "triggers": {k: {**v, "enabled": False}
                                 for k, v in CFG["triggers"].items()}}
    alert = A.build_alert(db, second, quiet)
    assert alert.items == []


# ── What is worth alerting on ───────────────────────────────────────────────

def test_a_baseline_run_does_not_alert_on_every_finding(db, cfg):
    """Everything is new in a first run. Posting all of it is a wall of text that
    trains people to ignore the channel."""
    first = _ingest(db, cfg, "r1")
    alert = A.build_alert(db, _run(db, first.run_id), CFG)
    assert not [i for i in alert.items if i.trigger == "new_finding"]
    assert any("first run" in note for note in alert.suppressed)


def test_second_run_alerts_only_on_findings_first_seen_there(db, cfg, two_runs):
    _first, second = two_runs
    alert = A.build_alert(db, second, CFG)
    for item in alert.items:
        if item.trigger != "new_finding":
            continue
        rule, _, asset = item.dedup_key.partition(":")[2].partition(":")
        row = db.execute(
            "SELECT first_seen_run_id FROM findings WHERE rule_id = ? "
            "AND asset_key = ?", (rule, asset)).fetchone()
        assert row["first_seen_run_id"] == second["id"]


def test_min_severity_is_respected(db, cfg, two_runs):
    _first, second = two_runs
    loud = {**CFG, "triggers": {**CFG["triggers"],
            "new_findings": {"enabled": True, "min_severity": "critical",
                             "max_listed": 50}}}
    alert = A.build_alert(db, second, loud)
    assert all(i.severity == "critical"
               for i in alert.items if i.trigger == "new_finding")


def test_truncation_is_announced_never_silent(db, cfg, two_runs):
    """A capped list that says nothing reads as "that was everything"."""
    _first, second = two_runs
    tight = {**CFG, "triggers": {**CFG["triggers"],
             "new_findings": {"enabled": True, "min_severity": "low",
                              "max_listed": 1}}}
    alert = A.build_alert(db, second, tight)
    listed = [i for i in alert.items if i.trigger == "new_finding"]
    assert len(listed) == 1
    assert any("not listed" in note for note in alert.suppressed)


def test_worsened_items_name_the_host(db, cfg, two_runs):
    """The change summary is written for a table with an asset column, so alone it
    reads "response_class: waf_blocked → live_content" with no host. Unactionable."""
    _first, second = two_runs
    alert = A.build_alert(db, second, CFG)
    worsened = [i for i in alert.items if i.trigger == "worsened"]
    for item in worsened:
        assert item.asset, "every worsened item must carry its asset"
        assert item.asset in item.headline


def test_classification_changes_are_not_alerted(db, cfg, two_runs):
    """An env or zone reclassification is a config edit of ours, and must never
    read to the on-call as attacker activity."""
    _first, second = two_runs
    db.execute(
        """INSERT INTO changes (project_id, run_id, asset_kind, asset_key, host,
                                change_type, field, before_json, after_json,
                                severity, direction, is_noisy, is_classification,
                                summary, created_at)
           VALUES (?,?,'endpoint','x.example.com:443','x.example.com','modified',
                   'env','"prod"','"dev"','high','worse',0,1,'env changed','now')""",
        (second["project_id"], second["id"]))
    db.commit()
    alert = A.build_alert(db, second, CFG)
    assert not any("env changed" in i.headline for i in alert.items)


def test_noisy_changes_are_not_alerted(db, cfg, two_runs):
    _first, second = two_runs
    db.execute(
        """INSERT INTO changes (project_id, run_id, asset_kind, asset_key, host,
                                change_type, field, before_json, after_json,
                                severity, direction, is_noisy, is_classification,
                                summary, created_at)
           VALUES (?,?,'endpoint','y.example.com:443','y.example.com','modified',
                   'content_sig','"a"','"b"','high','worse',1,0,'sig moved','now')""",
        (second["project_id"], second["id"]))
    db.commit()
    alert = A.build_alert(db, second, CFG)
    assert not any("sig moved" in i.headline for i in alert.items)


def test_takeover_alerts_say_candidate_not_confirmed(db, cfg, two_runs):
    """Ingest sends no packets, so nothing here is confirmed. An alert that
    overclaims gets the whole channel distrusted."""
    _first, second = two_runs
    alert = A.build_alert(db, second, CFG)
    for item in alert.items:
        if item.trigger == "takeover_candidate":
            assert "Possible" in item.headline or "candidate" in item.detail.lower()
            assert "verify" in item.detail


def test_an_empty_run_raises_a_data_quality_alert(db, cfg, two_runs):
    """A truncated scan produces fewer findings, which reads as an improvement.
    It has to be said out loud."""
    _first, second = two_runs
    db.execute("UPDATE runs SET endpoint_count = 0 WHERE id = ?", (second["id"],))
    db.commit()
    alert = A.build_alert(db, _run(db, second["id"]), CFG)
    assert any(i.trigger == "data_quality" for i in alert.items)


def test_nothing_new_produces_no_items(db, cfg):
    """Silence when nothing happened. A weekly all-clear trains people to ignore
    the channel, and then the real alert goes unread too."""
    first = _ingest(db, cfg, "r1")
    run = _run(db, first.run_id)
    alert = A.build_alert(db, run, {**CFG, "triggers": {
        "new_findings": {"enabled": True, "min_severity": "critical"},
        "worsened": {"enabled": True}, "takeover": {"enabled": False},
        "posture_drop": {"enabled": True}, "data_quality": {"enabled": True}}})
    assert not [i for i in alert.items if i.trigger in ("new_finding", "worsened")]


# ── The ledger ──────────────────────────────────────────────────────────────

def test_an_item_is_never_sent_twice(db, cfg, two_runs):
    _first, second = two_runs
    alert = A.build_alert(db, second, CFG)
    assert alert.items
    sinks.record(db, alert, "local", alert.items, "sent")

    again = A.build_alert(db, second, CFG)
    assert again.items == [], "the ledger must suppress a re-run"


def test_resend_bypasses_the_ledger(db, cfg, two_runs):
    _first, second = two_runs
    alert = A.build_alert(db, second, CFG)
    sinks.record(db, alert, "local", alert.items, "sent")
    forced = A.build_alert(db, second, CFG, include_sent=True)
    assert len(forced.items) == len(alert.items)


def test_a_failed_delivery_is_recorded_as_failed_not_sent(db, cfg, two_runs):
    """Recorded either way. A failure left absent from the ledger is a silent
    drop; recorded as `failed` it is visible and retryable."""
    _first, second = two_runs
    alert = A.build_alert(db, second, CFG)
    sinks.record(db, alert, "slack", alert.items, "failed", "HTTP 500")
    statuses = {r["status"] for r in db.execute(
        "SELECT status FROM notifications WHERE target = 'slack'")}
    assert statuses == {"failed"}
    # Still deliverable — a failure must not count as sent.
    assert A.build_alert(db, second, CFG).items


def test_the_ledger_is_per_target(db, cfg, two_runs):
    """A channel added later must be able to receive items an older channel got,
    or a new integration starts silent and looks broken."""
    _first, second = two_runs
    alert = A.build_alert(db, second, CFG)
    sinks.record(db, alert, "local", alert.items, "sent")
    sinks.record(db, alert, "slack", alert.items, "sent")
    counts = dict(db.execute(
        "SELECT target, COUNT(*) FROM notifications GROUP BY target").fetchall())
    assert counts["local"] == counts["slack"] == len(alert.items)


def test_recording_twice_does_not_duplicate_rows(db, cfg, two_runs):
    _first, second = two_runs
    alert = A.build_alert(db, second, CFG)
    sinks.record(db, alert, "local", alert.items, "sent")
    sinks.record(db, alert, "local", alert.items, "sent")
    total = db.execute("SELECT COUNT(*) AS n FROM notifications").fetchone()["n"]
    assert total == len(alert.items)


# ── Formatting ──────────────────────────────────────────────────────────────

def _fake(count, severity="high"):
    alert = A.Alert(project="P", run_key="run-x", run_id=1, project_id=1)
    alert.items = [A.AlertItem(trigger="new_finding", dedup_key=f"k{i}",
                               severity=severity, headline=f"issue {i}",
                               detail="detail", asset=f"h{i}.example.com")
                   for i in range(count)]
    return alert


def test_severity_never_travels_as_colour_alone():
    payload = sinks.slack_payload(_fake(1, "critical"))
    body = json.dumps(payload, ensure_ascii=False)
    assert "CRITICAL" in body, "the word, not only the glyph"
    assert "\U0001f534" in body, "and a glyph, not only the word"


def test_slack_payload_has_a_text_fallback():
    """`text` is the notification preview and the accessibility fallback."""
    payload = sinks.slack_payload(_fake(3))
    assert payload["text"]
    assert "P:" in payload["text"]


def test_slack_blocks_are_capped_and_the_cap_is_announced():
    """Slack rejects a message over 50 blocks outright, so an uncapped alert
    silently fails to arrive at all."""
    payload = sinks.slack_payload(_fake(100), max_blocks=40)
    assert len(payload["blocks"]) <= 40
    assert "not shown" in json.dumps(payload["blocks"])


def test_an_empty_alert_says_so_rather_than_rendering_nothing():
    payload = sinks.slack_payload(_fake(0))
    assert "Nothing new" in json.dumps(payload["blocks"])


def test_counts_read_as_english():
    """A rule-based pluraliser gave "10 worseneds" — the trigger name is an
    adjective."""
    one = _fake(1)
    assert one.summary_line() == "P: 1 new finding"
    assert _fake(4).summary_line() == "P: 4 new findings"

    alert = _fake(0)
    alert.items = [A.AlertItem(trigger="worsened", dedup_key="k", severity="high",
                               headline="h")]
    assert "endpoint got worse" in alert.summary_line()


def test_worst_severity_is_the_worst_present():
    alert = _fake(2, "low")
    alert.items.append(A.AlertItem(trigger="new_finding", dedup_key="z",
                                   severity="critical", headline="bad"))
    assert alert.worst == "critical"


# ── Redaction ───────────────────────────────────────────────────────────────

def test_redaction_without_a_host_list_refuses_to_send(two_runs, db):
    """`Redactor.text` only rewrites names it has been shown, so with no host
    list it is a no-op — a silent leak to the one channel that asked not to
    receive real names."""
    _first, second = two_runs
    alert = A.build_alert(db, second, CFG)
    sent, message = sinks.deliver(
        alert, {"name": "s", "kind": "slack", "url": "http://x", "redact": True},
        CFG, known_hosts=None, dry_run=True)
    assert sent is False
    assert "refusing to send" in message


def test_redaction_covers_the_dedup_key(db, cfg, two_runs):
    """The dedup key embeds the hostname, so copying it verbatim leaks every name
    the headline just hid — the same defect as the snapshot's dictionary keys."""
    _first, second = two_runs
    alert = A.build_alert(db, second, CFG)
    hosts = [r["host"] for r in db.execute("SELECT DISTINCT host FROM endpoints")]
    redacted = sinks._redacted(alert, hosts)
    blob = json.dumps(redacted.as_dict())
    assert "example.com" not in blob.replace(".example", "|")
    assert "org-" in blob
    for item in redacted.items:
        assert "example.com" not in item.dedup_key.replace(".example", "|")


def test_redaction_leaves_the_ledger_keyed_on_real_names(db, cfg, two_runs):
    """Otherwise dedup breaks: the same finding would re-alert under a new
    pseudonym every run."""
    _first, second = two_runs
    alert = A.build_alert(db, second, CFG)
    original = [i.dedup_key for i in alert.items]
    hosts = [r["host"] for r in db.execute("SELECT DISTINCT host FROM endpoints")]
    sinks._redacted(alert, hosts)
    assert [i.dedup_key for i in alert.items] == original


def test_redacted_alerts_say_they_are_redacted(db, cfg, two_runs):
    _first, second = two_runs
    alert = A.build_alert(db, second, CFG)
    hosts = [r["host"] for r in db.execute("SELECT DISTINCT host FROM endpoints")]
    redacted = sinks._redacted(alert, hosts)
    assert any("pseudonymised" in note for note in redacted.suppressed)


# ── Delivery ────────────────────────────────────────────────────────────────

def test_file_target_writes_json_lines(tmp_path, db, cfg, two_runs):
    _first, second = two_runs
    alert = A.build_alert(db, second, CFG)
    target = {"name": "local", "kind": "file", "path": "notifications.jsonl"}
    sent, message = sinks.deliver(alert, target, CFG, data_dir=tmp_path)
    assert sent, message
    lines = (tmp_path / "notifications.jsonl").read_text().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["item_count"] == len(alert.items)

    sinks.deliver(alert, target, CFG, data_dir=tmp_path)
    assert len((tmp_path / "notifications.jsonl").read_text().splitlines()) == 2


def test_a_leading_data_segment_is_not_doubled(tmp_path):
    """`notify.yaml` ships `data/notifications.jsonl`, which reads naturally from
    the project root but would become `data/data/...` if joined verbatim."""
    resolved = sinks._resolve_path("data/notifications.jsonl", tmp_path / "data")
    assert resolved == tmp_path / "data" / "notifications.jsonl"


def test_an_absolute_path_is_left_alone(tmp_path):
    target = tmp_path / "elsewhere" / "out.jsonl"
    assert sinks._resolve_path(str(target), tmp_path / "data") == target


def test_dry_run_writes_nothing(tmp_path, db, cfg, two_runs):
    _first, second = two_runs
    alert = A.build_alert(db, second, CFG)
    sent, message = sinks.deliver(
        alert, {"name": "local", "kind": "file", "path": "out.jsonl"},
        CFG, data_dir=tmp_path, dry_run=True)
    assert sent is False
    assert "dry run" in message
    assert not (tmp_path / "out.jsonl").exists()


def test_an_unknown_target_kind_is_reported(db, cfg, two_runs):
    _first, second = two_runs
    alert = A.build_alert(db, second, CFG)
    sent, message = sinks.deliver(alert, {"name": "x", "kind": "carrier-pigeon"},
                                 CFG)
    assert sent is False
    assert "unknown target kind" in message


def test_a_4xx_is_not_retried(monkeypatch):
    """A rejected webhook URL will not start working on the second attempt, and
    hammering it is the wrong response."""
    import urllib.error

    attempts = []

    def fake(request, timeout=None):
        attempts.append(1)
        raise urllib.error.HTTPError(request.full_url, 404, "gone", {}, None)

    monkeypatch.setattr("urllib.request.urlopen", fake)
    sent, message = sinks._post("http://x", {"a": 1}, 1, retries=3,
                                retry_delay=0)
    assert sent is False
    assert len(attempts) == 1
    assert "404" in message


def test_a_5xx_is_retried(monkeypatch):
    import urllib.error

    attempts = []

    def fake(request, timeout=None):
        attempts.append(1)
        raise urllib.error.HTTPError(request.full_url, 503, "busy", {}, None)

    monkeypatch.setattr("urllib.request.urlopen", fake)
    sent, _message = sinks._post("http://x", {"a": 1}, 1, retries=2,
                                 retry_delay=0)
    assert sent is False
    assert len(attempts) == 3


def test_alerts_module_reaches_no_network():
    """The judgement calls live in a module a test can drive with no webhook."""
    source = Path(A.__file__).read_text(encoding="utf-8")
    for forbidden in ("urlopen", "urllib.request", "socket."):
        assert forbidden not in source, forbidden
