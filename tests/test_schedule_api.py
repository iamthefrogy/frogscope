"""Scheduled scanning (v2): API validation, CRUD, and next-run computation.

Most of this needs no live scan at all — creation validation and the CRUD
round-trip are pure logic. Only the tick()/run-now tests actually execute a
scan, and only need subfinder+httpx (CORE), not the correlation tools.
"""

from __future__ import annotations

import shutil
from datetime import UTC, datetime, timedelta

import pytest

from frogscope.config import load_config
from frogscope.db.connection import connect
from frogscope.scan.scheduler import Scheduler, next_run_at
from frogscope.server import create_app

pytestmark = pytest.mark.skipif(
    not (shutil.which("subfinder") and shutil.which("httpx")),
    reason="subfinder/httpx not installed",
)


@pytest.fixture()
def cfg(tmp_path, monkeypatch):
    conf = load_config()
    monkeypatch.setattr(conf, "data_dir", tmp_path)
    return conf


@pytest.fixture()
def client(cfg, monkeypatch):
    monkeypatch.setattr("frogscope.config.load_config", lambda *a, **k: cfg)
    app = create_app(cfg)
    app.config.update(TESTING=True)
    with app.test_client() as c:
        c.environ_base["HTTP_X_AUTH_KEY"] = app.config["FROGSCOPE_AUTH_KEY"]
        yield c


@pytest.fixture()
def project(client):
    client.post("/api/projects", json={"name": "sched-test"})
    return "sched-test"


def _create(client, project, **overrides):
    payload = {
        "name": "nightly", "targets": ["example.com"], "profile": "web",
        "preset": "daily", "time_of_day": "03:00",
        "authorised": True, "subfinder": False,
    }
    payload.update(overrides)
    return client.post(f"/api/projects/{project}/schedules", json=payload)


# ── next_run_at: pure logic, no server needed ───────────────────────────────

def test_daily_next_run_is_tomorrow_if_the_time_already_passed_today():
    now = datetime(2026, 1, 15, 10, 0, tzinfo=UTC)  # 10:00, target is 03:00
    nxt = datetime.fromisoformat(next_run_at("daily", "03:00", None, now=now))
    assert nxt.date() == (now + timedelta(days=1)).date()
    assert (nxt.hour, nxt.minute) == (3, 0)


def test_daily_next_run_is_today_if_the_time_has_not_passed_yet():
    now = datetime(2026, 1, 15, 1, 0, tzinfo=UTC)  # 01:00, target is 03:00
    nxt = datetime.fromisoformat(next_run_at("daily", "03:00", None, now=now))
    assert nxt.date() == now.date()


def test_weekly_next_run_lands_on_the_requested_weekday():
    now = datetime(2026, 1, 15, 12, 0, tzinfo=UTC)  # a Thursday
    nxt = datetime.fromisoformat(next_run_at("weekly", "03:00", 0, now=now))  # Monday
    assert nxt.weekday() == 0
    assert nxt > now


def test_hourly_next_run_is_within_the_next_hour():
    now = datetime(2026, 1, 15, 12, 30, tzinfo=UTC)
    nxt = datetime.fromisoformat(next_run_at("hourly", None, None, now=now))
    assert now < nxt <= now + timedelta(hours=1)


def test_missing_time_of_day_defaults_to_an_off_hours_time():
    nxt = datetime.fromisoformat(
        next_run_at("daily", None, None, now=datetime(2026, 1, 15, 1, 0, tzinfo=UTC)))
    assert (nxt.hour, nxt.minute) == (3, 0)


# ── Creation validation ──────────────────────────────────────────────────────

def test_a_schedule_needs_a_name(client, project):
    resp = _create(client, project, name="")
    assert resp.status_code == 400


def test_a_schedule_needs_explicit_authorisation(client, project):
    resp = _create(client, project, authorised=False)
    assert resp.status_code == 400
    assert "authoris" in resp.get_json()["error"].lower()


def test_an_unknown_preset_is_rejected(client, project):
    resp = _create(client, project, preset="fortnightly")
    assert resp.status_code == 400


def test_a_schedule_has_no_configurable_host_cap(client, project):
    """There is nothing left to validate here — `MAX_HOSTS` (options.py) is
    the one unconditional ceiling, not user input, so a schedule always
    auto-approves everything it finds up to that same limit every other scan
    already respects."""
    from frogscope.scan import options as scan_options

    created = _create(client, project).get_json()["schedule"]
    assert created["max_hosts_cap"] == scan_options.MAX_HOSTS


def test_bad_targets_are_rejected_the_same_way_a_manual_scan_would_be(client, project):
    resp = _create(client, project, targets=["*.example.com"])
    assert resp.status_code == 400


def test_target_kind_is_derived_from_the_targets(client, project):
    resp = _create(client, project, targets=["203.0.113.0/28"])
    assert resp.status_code == 201
    assert resp.get_json()["schedule"]["target_kind"] == "cidr"

    resp = _create(client, project, name="mixed-one",
                   targets=["example.com", "203.0.113.5"])
    assert resp.get_json()["schedule"]["target_kind"] == "mixed"


def test_unknown_project_is_a_404(client):
    resp = _create(client, "no-such-project")
    assert resp.status_code == 404


# ── CRUD round trip ──────────────────────────────────────────────────────────

def test_create_list_patch_delete_round_trip(client, project):
    created = _create(client, project).get_json()["schedule"]
    sid = created["id"]

    listed = client.get(f"/api/projects/{project}/schedules").get_json()["schedules"]
    assert any(s["id"] == sid for s in listed)

    patched = client.patch(f"/api/schedules/{sid}",
                           json={"enabled": False}).get_json()["schedule"]
    assert patched["enabled"] == 0

    deleted = client.delete(f"/api/schedules/{sid}").get_json()
    assert deleted["deleted"] is True

    listed_after = client.get(f"/api/projects/{project}/schedules").get_json()["schedules"]
    assert not any(s["id"] == sid for s in listed_after)


def test_patching_the_preset_recomputes_next_run_at(client, project):
    created = _create(client, project, preset="daily", time_of_day="03:00").get_json()["schedule"]
    patched = client.patch(f"/api/schedules/{created['id']}",
                           json={"preset": "hourly"}).get_json()["schedule"]
    assert patched["preset"] == "hourly"
    assert patched["next_run_at"] != created["next_run_at"]


def test_modifying_an_unknown_schedule_is_a_404(client):
    assert client.patch("/api/schedules/999999", json={}).status_code == 404
    assert client.delete("/api/schedules/999999").status_code == 404


# ── Actually running one (needs subfinder+httpx) ────────────────────────────

def test_run_now_executes_immediately_and_records_the_run(client, project):
    created = _create(client, project).get_json()["schedule"]
    resp = client.post(f"/api/schedules/{created['id']}/run-now")
    assert resp.status_code == 200
    schedule = resp.get_json()["schedule"]
    assert schedule["last_run_id"] is not None
    assert schedule["last_skip_reason"] == ""


def test_tick_processes_a_due_schedule_and_reschedules_it(client, project, cfg):
    created = _create(client, project).get_json()["schedule"]
    sid = created["id"]

    # Force it overdue, as if the clock had already passed next_run_at.
    conn = connect(cfg.db_path)
    conn.execute("UPDATE schedules SET next_run_at = ? WHERE id = ?",
                ((datetime.now(UTC) - timedelta(minutes=5)).isoformat(), sid))
    conn.commit()
    conn.close()

    processed = Scheduler(cfg).tick()
    assert sid in processed

    refreshed = client.get(f"/api/projects/{project}/schedules").get_json()["schedules"][0]
    assert refreshed["last_run_id"] is not None
    # Rescheduled into the future, not left overdue forever.
    assert datetime.fromisoformat(refreshed["next_run_at"]) > datetime.now(UTC)


def test_tick_skips_cleanly_when_targets_resolve_to_nothing(client, project):
    """A schedule whose targets can't be resolved at all (`EmptyResult`,
    scan/runner.py) skips cleanly and records why, rather than raising out
    of the scheduler loop — same handling `ScanError`/`Cancelled` already
    get."""
    created = _create(
        client, project,
        targets=["this-domain-does-not-exist-frogscope-test.invalid"],
    ).get_json()["schedule"]
    resp = client.post(f"/api/schedules/{created['id']}/run-now")
    assert resp.status_code == 200
    schedule = resp.get_json()["schedule"]
    assert schedule["last_skip_reason"] != ""
