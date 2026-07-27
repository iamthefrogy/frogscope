"""v2 network/certificate API routes.

Uses the same Flask test-client fixture pattern as test_manage.py, but seeds
data through a real correlated scan rather than the plain sample.csv fixture
— these routes only have something to show once dnsx/mapcidr/tlsx have run.
"""

from __future__ import annotations

import shutil

import pytest

from frogscope.config import load_config
from frogscope.db.connection import connect
from frogscope.db.migrate import migrate
from frogscope.ingest import pipeline
from frogscope.scan.options import parse
from frogscope.scan.runner import ScanRun
from frogscope.server import create_app

pytestmark = pytest.mark.skipif(
    not (shutil.which("dnsx") and shutil.which("mapcidr") and shutil.which("tlsx")),
    reason="dnsx/mapcidr/tlsx not installed — these tests need the real binaries",
)


@pytest.fixture()
def cfg(tmp_path, monkeypatch):
    conf = load_config()
    monkeypatch.setattr(conf, "data_dir", tmp_path)
    return conf


@pytest.fixture()
def correlated_run(cfg):
    """A real correlated scan of a known-bad cert, so certs/discovery/network
    routes all have something to return."""
    conn = connect(cfg.db_path)
    migrate(conn)
    options = parse({
        "targets": ["self-signed.badssl.com"], "authorised": True,
        "subfinder": False,
    })
    run = ScanRun(options)
    csv_path = run.run()
    result = pipeline.ingest(
        conn, cfg, csv_path, project="net-api-test", supervised=True,
        trust_mtime=False, correlation=run.artifacts.get("correlation"),
    )
    conn.commit()
    conn.close()
    return result


@pytest.fixture()
def client(cfg, monkeypatch):
    monkeypatch.setattr("frogscope.config.load_config", lambda *a, **k: cfg)
    app = create_app(cfg)
    app.config.update(TESTING=True)
    with app.test_client() as c:
        # v2: every /api/* route needs the access key now — see server.py's
        # before_request gate, and test_manage.py's client fixture for why
        # environ_base (not a per-call header) is the right way to do this.
        c.environ_base["HTTP_X_AUTH_KEY"] = app.config["FROGSCOPE_AUTH_KEY"]
        yield c


def test_network_summary_reports_correlation_ran(client, correlated_run):
    resp = client.get("/api/network/summary?project=net-api-test")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["correlated"] is True
    assert data["certificates"] >= 1
    assert {c["tool"] for c in data["collectors"]} == {"dnsx", "mapcidr", "tlsx"}


def test_certs_list_and_detail_round_trip(client, correlated_run):
    listed = client.get("/api/certs?project=net-api-test").get_json()
    assert listed["total"] >= 1
    sha = listed["rows"][0]["cert_sha256"]

    detail = client.get(f"/api/certs/{sha}?project=net-api-test").get_json()
    assert detail["certificate"]["cert_sha256"] == sha
    # SQLite stores booleans as 0/1, and that survives JSON serialisation as
    # a plain int, not `true`/`false` — truthy check, not `is True`.
    assert detail["certificate"]["self_signed"]
    assert any(n["cert_sha256"] == sha for n in detail["names"])


def test_certs_status_filter_narrows_to_broken(client, correlated_run):
    broken = client.get(
        "/api/certs?project=net-api-test&status=self_signed").get_json()
    assert all(r["self_signed"] for r in broken["rows"])


def test_network_ips_list_and_detail_round_trip(client, correlated_run):
    listed = client.get("/api/network/ips?project=net-api-test").get_json()
    assert listed["total"] >= 1
    ip = listed["rows"][0]["ip"]

    detail = client.get(f"/api/network/ips/{ip}?project=net-api-test").get_json()
    assert detail["ip"]["ip"] == ip
    assert isinstance(detail["endpoints"], list)


def test_graph_ip_node_has_edges(client, correlated_run):
    ip = client.get("/api/network/ips?project=net-api-test").get_json()["rows"][0]["ip"]
    graph = client.get(f"/api/graph/ip/{ip}?project=net-api-test").get_json()
    assert graph["node"]["kind"] == "ip"
    assert not graph["truncated"]
    assert isinstance(graph["edges"], list)


def test_graph_unknown_kind_is_rejected(client, correlated_run):
    resp = client.get("/api/graph/nonsense/whatever?project=net-api-test")
    assert resp.status_code == 400


def test_scan_tools_ready_ignores_correlation_tools(client, monkeypatch):
    """`ready` must reflect subfinder/httpx only — requiring dnsx/mapcidr/tlsx
    too would report a plain domain scan as unavailable on a machine that
    simply never installed the tools that power DNS/network/TLS analysis
    (unconditional now, but degrading gracefully rather than blocking a
    scan when absent)."""
    from frogscope.scan import tools as tools_mod

    monkeypatch.setattr(tools_mod, "find",
                        lambda name: "" if name in tools_mod.EXTRA else f"/bin/{name}")
    resp = client.get("/api/scan/tools")
    data = resp.get_json()
    assert data["ready"] is True


def test_endpoint_detail_includes_network_and_cert_blocks(client, correlated_run):
    rows = client.get(
        "/api/endpoints/query?project=net-api-test&page_size=10").get_json()["rows"]
    assert rows, "expected at least one endpoint from the correlated scan"
    key = rows[0]["endpoint_key"]
    detail = client.get(
        f"/api/endpoints/{key}?project=net-api-test").get_json()
    assert "network" in detail
    assert "cert" in detail
    assert "same_cert" in detail
