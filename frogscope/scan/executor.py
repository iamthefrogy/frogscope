"""The part of running a scan that must never drift between callers.

`POST /api/scan` (routes.py) and the scheduler (scheduler.py, v2) each build
and run their own `ScanRun` — they need different bookkeeping around it (an
in-memory job dict polled by the browser vs. a `schedules` table row) — but
what happens once `ScanRun.run()` succeeds is identical either way: ingest
the CSV, and record that this run came from a scan rather than an upload.
Keeping that one part here means the two paths cannot quietly diverge (e.g.
one remembering `target_kind`, the other forgetting it).

`SCAN_SLOT` lives here too, for the same reason: both callers need to
acquire the exact same semaphore, not two separate ones that would let a
scheduled run and a manual one execute at the same time.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path

from ..config import Config
from ..db.connection import connect
from ..ingest import pipeline
from .runner import ScanRun

# One scan at a time, process-wide. Two concurrent wide scans against the
# same estate is a self-inflicted denial of service.
SCAN_SLOT = threading.Semaphore(1)


def ingest_scan_result(cfg: Config, csv_path: Path, options, run: ScanRun,
                       started_at: str, *, project: str,
                       project_name: str | None = None,
                       label: str | None = None) -> pipeline.IngestResult:
    """Ingest the CSV a completed `ScanRun` produced, and mark the resulting
    run as scan-sourced. Identical path to an uploaded file otherwise — a
    scan and an upload must produce the same run, or the analysis would
    depend on how the data arrived.
    """
    conn = connect(cfg.db_path)
    try:
        result = pipeline.ingest(
            conn, cfg, csv_path, project=project, project_name=project_name,
            label=label,
            # The scan orchestrator started httpx and watched it exit, so
            # completeness is observed rather than inferred.
            supervised=True,
            trust_mtime=False,
            # The scan's own clock, so a scanner that omits per-row
            # timestamps still lands correctly in the timeline.
            scanned_at=started_at,
            # NOT blanket-True: `hosts_submitted`/`ports_prescoped` below let
            # `quality.truncation_check` tell a legitimate target-list/
            # profile change (auto-permitted, same as before) apart from a
            # truncated run (same host list, far fewer rows) — the case a
            # hardcoded `allow_drift=True` used to let through silently.
            allow_drift=False,
            hosts_submitted=run.progress.hosts_total or None,
            ports_prescoped=run.ports_prescoped,
            correlation=run.artifacts.get("correlation"),
        )
        scan_meta = {
            **options.as_dict(),
            # Every tool call that exhausted its retries this run — kept
            # here so run history shows it later, not just the live progress
            # log (which only ever shows its last 40 lines to the UI).
            "failures": run.progress.failures,
        }
        conn.execute(
            "UPDATE runs SET source_kind = 'scan', scan_json = ?, "
            "target_kind = ? WHERE id = ?",
            (json.dumps(scan_meta), options.target_kind, result.run_id))
        conn.commit()
    finally:
        conn.close()
    return result
