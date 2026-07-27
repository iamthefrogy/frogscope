"""The app-wide access-key gate (v2).

Unlike test_manage.py/test_network_api.py, these tests do NOT pre-attach the
header via environ_base — the whole point here is to exercise the gate
itself, not work around it.
"""

from __future__ import annotations

import pytest

from frogscope.auth import ENV_VAR, KEY_FILE_NAME, get_or_create_key, rotate_key
from frogscope.config import load_config
from frogscope.server import create_app


@pytest.fixture()
def cfg(tmp_path, monkeypatch):
    conf = load_config()
    monkeypatch.setattr(conf, "data_dir", tmp_path)
    return conf


# ── auth.py: key generation ──────────────────────────────────────────────────

def test_first_call_generates_and_persists_a_key(tmp_path):
    key, created = get_or_create_key(tmp_path)
    assert created is True
    assert len(key) >= 32
    assert (tmp_path / KEY_FILE_NAME).read_text(encoding="utf-8").strip() == key


def test_second_call_reuses_the_stored_key_without_reporting_creation(tmp_path):
    first, _ = get_or_create_key(tmp_path)
    second, created = get_or_create_key(tmp_path)
    assert second == first
    assert created is False


def test_env_var_overrides_the_stored_file_entirely(tmp_path, monkeypatch):
    get_or_create_key(tmp_path)  # a file-backed key already exists
    monkeypatch.setenv(ENV_VAR, "explicit-key-from-compose")
    key, created = get_or_create_key(tmp_path)
    assert key == "explicit-key-from-compose"
    assert created is False


def test_rotate_generates_a_different_key_and_overwrites_the_file(tmp_path):
    original, _ = get_or_create_key(tmp_path)
    rotated = rotate_key(tmp_path)
    assert rotated != original
    assert (tmp_path / KEY_FILE_NAME).read_text(encoding="utf-8").strip() == rotated


# ── server.py: the before_request gate itself ───────────────────────────────

@pytest.fixture()
def app(cfg, monkeypatch):
    monkeypatch.setattr("frogscope.config.load_config", lambda *a, **k: cfg)
    application = create_app(cfg)
    application.config.update(TESTING=True)
    return application


def test_ungated_paths_need_no_key(app):
    client = app.test_client()
    assert client.get("/").status_code == 200
    assert client.get("/healthz").status_code == 200


def test_api_routes_reject_a_request_with_no_key(app):
    client = app.test_client()
    resp = client.get("/api/runs")
    assert resp.status_code == 401


def test_api_routes_reject_the_wrong_key(app):
    client = app.test_client()
    resp = client.get("/api/runs", headers={"X-Auth-Key": "not-the-key"})
    assert resp.status_code == 401


def test_api_routes_accept_the_real_key(app):
    client = app.test_client()
    real_key = app.config["FROGSCOPE_AUTH_KEY"]
    resp = client.get("/api/runs", headers={"X-Auth-Key": real_key})
    assert resp.status_code == 200


def test_verify_endpoint_is_reachable_with_no_key_at_all(app):
    """The one API route exempt from the gate — checking a submitted key is
    the whole point of it, so it cannot itself require one."""
    client = app.test_client()
    resp = client.post("/api/auth/verify", json={"key": ""})
    assert resp.status_code == 401  # reachable, correctly rejects a blank key
    resp = client.post("/api/auth/verify", json={"key": app.config["FROGSCOPE_AUTH_KEY"]})
    assert resp.status_code == 200


def test_rotate_endpoint_requires_the_current_key_first(app):
    client = app.test_client()
    real_key = app.config["FROGSCOPE_AUTH_KEY"]

    # No key at all: the before_request gate blocks it before the route ever runs.
    assert client.post("/api/auth/rotate").status_code == 401

    resp = client.post("/api/auth/rotate", headers={"X-Auth-Key": real_key})
    assert resp.status_code == 200
    new_key = resp.get_json()["key"]
    assert new_key != real_key

    # The old key is dead immediately; the new one works.
    assert client.get("/api/runs", headers={"X-Auth-Key": real_key}).status_code == 401
    assert client.get("/api/runs", headers={"X-Auth-Key": new_key}).status_code == 200
