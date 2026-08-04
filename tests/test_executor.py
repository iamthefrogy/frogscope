"""frogscope.scan.executor.ingest_scan_result: the exact call every
scan-triggered ingest (manual and scheduled) goes through — regression
coverage for the bug where a hardcoded `allow_drift=True` silently accepted
a truncated run every time."""

from __future__ import annotations

from types import SimpleNamespace

from frogscope.config import load_config
from frogscope.db.migrate import migrate
from frogscope.db.connection import connect
from frogscope.ingest import pipeline
from frogscope.scan import executor


def _fake_options():
    return SimpleNamespace(
        as_dict=lambda: {"domains": ["example.com"], "rate_limit": 60},
        target_kind="domain",
    )


def _fake_run(*, hosts_total=300, ports_prescoped=True, failures=None):
    return SimpleNamespace(
        progress=SimpleNamespace(hosts_total=hosts_total,
                                 failures=failures or []),
        ports_prescoped=ports_prescoped,
        artifacts={},
    )


def test_ingest_scan_result_does_not_force_allow_drift(tmp_path, monkeypatch):
    conf = load_config()
    monkeypatch.setattr(conf, "data_dir", tmp_path)
    conn = connect(conf.db_path)
    migrate(conn)
    conn.close()

    captured = {}

    def fake_ingest(conn, cfg, csv_path, **kwargs):
        captured.update(kwargs)
        return pipeline.IngestResult(
            run_id=1, run_key="r", project_id=1, row_count=1,
            endpoint_count=1, host_count=1, collapse={})

    monkeypatch.setattr(pipeline, "ingest", fake_ingest)
    # executor.py does `from ..ingest import pipeline` then calls
    # `pipeline.ingest(...)` — patching the module attribute above is what
    # that lookup actually sees at call time.

    csv_path = tmp_path / "scan.csv"
    csv_path.write_text("host,port\na.example.com,443\n", encoding="utf-8")

    executor.ingest_scan_result(
        conf, csv_path, _fake_options(), _fake_run(),
        "2026-08-04T00:00:00Z", project="p1")

    assert captured["allow_drift"] is False
    assert captured["hosts_submitted"] == 300
    assert captured["ports_prescoped"] is True
    assert captured["supervised"] is True
