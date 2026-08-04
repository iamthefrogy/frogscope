"""frogscope.scan.preflight: fail fast on a broken DNS/network before a scan
starts spending any time or sending any traffic."""

from __future__ import annotations

import socket

import pytest

from frogscope.scan import options as opts
from frogscope.scan import preflight


def _domain_options():
    return opts.parse({"domains": ["example.com"], "authorised": True})


def _ip_options():
    return opts.parse({"targets": ["1.2.3.4"], "authorised": True})


def test_passes_when_dns_and_network_are_fine(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [("dummy",)])
    monkeypatch.setattr(socket, "create_connection",
                        lambda *a, **k: _FakeSocket())
    preflight.run(_domain_options())  # must not raise


def test_raises_when_dns_resolution_fails(monkeypatch):
    monkeypatch.setattr(
        socket, "getaddrinfo",
        lambda *a, **k: (_ for _ in ()).throw(OSError("no resolver")))
    monkeypatch.setattr(socket, "create_connection",
                        lambda *a, **k: _FakeSocket())
    with pytest.raises(preflight.PreflightError) as caught:
        preflight.run(_domain_options())
    assert "DNS" in str(caught.value)


def test_raises_when_outbound_network_is_blocked(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [("dummy",)])
    monkeypatch.setattr(
        socket, "create_connection",
        lambda *a, **k: (_ for _ in ()).throw(OSError("no route")))
    with pytest.raises(preflight.PreflightError) as caught:
        preflight.run(_domain_options())
    assert "network" in str(caught.value) or "reach" in str(caught.value)


def test_dns_check_is_skipped_for_a_pure_ip_scan(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("getaddrinfo should not be called for an IP-only scan")

    monkeypatch.setattr(socket, "getaddrinfo", boom)
    monkeypatch.setattr(socket, "create_connection",
                        lambda *a, **k: _FakeSocket())
    preflight.run(_ip_options())  # must not raise, must not touch DNS


def test_skip_env_var_bypasses_every_check(monkeypatch):
    monkeypatch.setenv(preflight.SKIP_ENV_VAR, "1")

    def boom(*a, **k):
        raise AssertionError("no check should run when preflight is skipped")

    monkeypatch.setattr(socket, "getaddrinfo", boom)
    monkeypatch.setattr(socket, "create_connection", boom)
    preflight.run(_domain_options())  # must not raise


class _FakeSocket:
    def close(self) -> None:
        pass
