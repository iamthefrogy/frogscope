"""Per-project scheduled scanning (v2) — for an estate that keeps changing
while nobody has a browser tab open.

A background thread, not a new dependency: this project deliberately ships
with two runtime dependencies (Flask, PyYAML — see `pyproject.toml` and the
README's own count of them), and a cron-like tick loop checking one table
every minute is a few dozen lines of stdlib, not reason enough to add
APScheduler.

Every scheduled run goes through `scan/executor.py`, the exact path a manual
scan does — so a run this scheduler triggers and one a person clicked
"Start scan" for are indistinguishable once ingested. The one thing a
schedule's options carry that a manual scan's never do: `approved_hosts` is
pre-set to the schedule's own `max_hosts_cap`, so `NeedsApproval` clears
automatically up to that ceiling. Nobody is there at 3am to click "approve",
so the ceiling has to be agreed on when the schedule is created instead — and
a run that would exceed it is skipped and recorded, never silently probed
past what was agreed.
"""

from __future__ import annotations

import json
import threading
from datetime import UTC, datetime, timedelta

from ..config import Config
from ..db.connection import connect
from . import executor
from . import options as opts
from .runner import Cancelled, NeedsApproval, ScanError, ScanRun

# One check a minute is frequent enough that "daily at 03:00" fires within a
# minute of meaning it, and cheap enough that it costs nothing between ticks.
TICK_SECONDS = 60

# No time_of_day set on a schedule defaults here — an unattended scan
# belongs in a quiet window, not whenever someone happened to leave the
# field blank.
DEFAULT_TIME = "03:00"


def _parse_time(value: str | None) -> tuple[int, int]:
    text = (value or DEFAULT_TIME).strip()
    try:
        hh, mm = text.split(":")
        return int(hh) % 24, int(mm) % 60
    except (ValueError, AttributeError):
        return 3, 0


def next_run_at(preset: str, time_of_day: str | None,
                day_of_week: int | None, *, now: datetime | None = None) -> str:
    """The next fire time for a schedule, computed fresh each time a run
    completes (or right after creation) rather than as a fixed recurrence
    rule — simpler to reason about, and immune to drift from a missed tick
    (a server that was down at 03:00 just runs at the next tick that notices
    it is overdue, instead of never).
    """
    now = now or datetime.now(UTC)
    hh, mm = _parse_time(time_of_day)

    if preset == "hourly":
        candidate = now.replace(minute=mm % 60, second=0, microsecond=0)
        if candidate <= now:
            candidate += timedelta(hours=1)
        return candidate.isoformat()

    if preset == "weekly":
        target_dow = day_of_week if day_of_week is not None else 0
        candidate = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
        days_ahead = (target_dow - candidate.weekday()) % 7
        candidate += timedelta(days=days_ahead)
        if candidate <= now:
            candidate += timedelta(days=7)
        return candidate.isoformat()

    # daily (default preset)
    candidate = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
    if candidate <= now:
        candidate += timedelta(days=1)
    return candidate.isoformat()


class Scheduler:
    """One instance per running app. `start()`/`stop()` are idempotent, so
    `create_app()` can call `start()` unconditionally without worrying about
    Werkzeug's `--reload` starting it twice — see server.py for the actual
    reloader guard, which is the more important half of that story."""

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="frogscope-scheduler")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _loop(self) -> None:
        while not self._stop.wait(TICK_SECONDS):
            try:
                self.tick()
            except Exception as exc:  # a bad tick must never kill the loop
                print(f"scheduler: tick failed: {type(exc).__name__}: {exc}",
                      flush=True)

    def tick(self) -> list[int]:
        """Run every due schedule once. Returns the schedule ids processed —
        mainly so a test can assert on it without inspecting the database."""
        conn = connect(self.cfg.db_path)
        try:
            now = datetime.now(UTC).replace(microsecond=0).isoformat()
            due = [
                dict(row) for row in conn.execute(
                    "SELECT s.*, p.slug AS project_slug FROM schedules s "
                    "JOIN projects p ON p.id = s.project_id "
                    "WHERE s.enabled = 1 AND s.next_run_at <= ?", (now,))
            ]
            for schedule in due:
                self._run_one(conn, schedule)
            return [s["id"] for s in due]
        finally:
            conn.close()

    def _run_one(self, conn, schedule: dict) -> None:
        nxt = next_run_at(schedule["preset"], schedule["time_of_day"],
                          schedule["day_of_week"])

        try:
            targets = json.loads(schedule["targets_json"] or "[]")
            flags = json.loads(schedule["flags_json"] or "{}")
            # `schedule["correlate_json"]` is no longer read: DNS/network
            # analysis and TLS certificate reading both run unconditionally
            # now, so there is nothing left for a per-schedule correlate
            # setting to gate. The column stays in the schema (harmless,
            # unused) rather than a migration to drop it.
            payload = {
                "targets": targets,
                "profile": schedule["profile"],
                "flags": flags,
                "subfinder": bool(schedule["subfinder"]),
                "authorised": True,
                # The unattended-approval policy: proceed automatically up to
                # this ceiling, never past it.
                "approved_hosts": int(schedule["max_hosts_cap"]),
            }
            options = opts.parse(payload)
        except opts.OptionError as exc:
            self._record(conn, schedule["id"], nxt, skip_reason=str(exc))
            return

        started_at = datetime.now(UTC).replace(microsecond=0).isoformat()
        run = ScanRun(options)
        try:
            csv_path = run.run()
        except NeedsApproval as pause:
            self._record(
                conn, schedule["id"], nxt,
                skip_reason=(
                    f"{len(pause.hosts)} hosts found, over this schedule's "
                    f"{schedule['max_hosts_cap']}-host cap — run skipped rather "
                    f"than probing more than was agreed"))
            return
        except (ScanError, Cancelled) as exc:
            self._record(conn, schedule["id"], nxt, skip_reason=str(exc))
            return

        try:
            result = executor.ingest_scan_result(
                self.cfg, csv_path, options, run, started_at,
                project=schedule["project_slug"], label=schedule["name"])
        except Exception as exc:  # ingest failing must not wedge the schedule
            self._record(conn, schedule["id"], nxt,
                        skip_reason=f"{type(exc).__name__}: {exc}")
            return

        self._record(conn, schedule["id"], nxt, run_id=result.run_id)

    def _record(self, conn, schedule_id: int, next_at: str, *,
               run_id: int | None = None, skip_reason: str = "") -> None:
        now = datetime.now(UTC).replace(microsecond=0).isoformat()
        conn.execute(
            "UPDATE schedules SET last_run_at = ?, next_run_at = ?, "
            "last_run_id = COALESCE(?, last_run_id), last_skip_reason = ?, "
            "updated_at = ? WHERE id = ?",
            (now, next_at, run_id, skip_reason, now, schedule_id))
        conn.commit()
