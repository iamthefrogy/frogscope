"""JSON API for the SPA."""

from __future__ import annotations

import json
import re
import tempfile
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from flask import Blueprint, Response, current_app, jsonify, request

from ..ingest import pipeline, quality
from ..query import facets
from ..query.filters import FilterError
from ..scan import executor
from ._db import get_catalog, get_config, get_db, resolve_run

api = Blueprint("api", __name__, url_prefix="/api")

# Upload jobs. A lock-guarded dict is enough — ingest takes seconds and the app
# binds to localhost, so there is no need for a real queue.
_JOBS: dict[str, dict[str, Any]] = {}
_JOBS_LOCK = threading.Lock()


def _row_to_dict(row) -> dict:
    out = dict(row)
    for key in ("summary_json", "warnings_json"):
        if key in out and out[key]:
            try:
                out[key.removesuffix("_json")] = json.loads(out[key])
            except json.JSONDecodeError:
                pass
            out.pop(key, None)
    return out


@api.errorhandler(FilterError)
def _bad_filter(exc: FilterError):
    return jsonify({"error": str(exc)}), 400


# ── Auth (v2) ────────────────────────────────────────────────────────────────
#
# `/api/auth/verify` is the one route reachable with no key at all (see
# server.py's `_UNGATED_PATHS`) — checking a submitted key is the whole point
# of it. Every other route, `/api/auth/rotate` included, is already behind
# the `before_request` gate: reaching `rotate` means the caller already has
# a valid key, which is exactly the authorisation a rotation should require.

@api.post("/auth/verify")
def auth_verify():
    import secrets as _secrets

    submitted = (request.get_json(silent=True) or {}).get("key", "")
    if _secrets.compare_digest(submitted, current_app.config["FROGSCOPE_AUTH_KEY"]):
        return jsonify({"ok": True})
    return jsonify({"error": "incorrect key"}), 401


@api.post("/auth/rotate")
def auth_rotate():
    from ..auth import rotate_key

    cfg = get_config()
    new_key = rotate_key(cfg.data_dir)
    current_app.config["FROGSCOPE_AUTH_KEY"] = new_key
    return jsonify({"key": new_key})


# ── Meta ────────────────────────────────────────────────────────────────────

@api.get("/columns")
def columns():
    catalog = get_catalog()
    payload = catalog.as_dict()

    run = resolve_run(get_db(), request.args.get("run"), request.args.get("project"))
    if run:
        fill = facets.visible_columns(get_db(), run["id"])
        payload["source_fill"] = fill
        # Auto-hide any column whose underlying httpx field was entirely empty
        # for this run. That makes today's empty columns a non-issue and makes
        # them appear automatically when richer flags are used.
        payload["empty_source_columns"] = sorted(
            name for name, pct in fill.items() if pct == 0.0
        )
    return jsonify(payload)


@api.get("/projects")
def projects():
    from ..ingest.store import list_projects
    return jsonify({"projects": [dict(r) for r in list_projects(get_db())]})


_SLUG = re.compile(r"^[a-z0-9][a-z0-9-]{0,48}[a-z0-9]$")


def _slugify(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", (text or "").strip().lower()).strip("-")
    return slug[:50].strip("-")


@api.post("/projects")
def create_project():
    """Create a project from the UI.

    The slug is derived from the name unless one is given, because a user typing
    "Acme Corp" should not have to know that the CLI wants `acme-corp`.
    """
    payload = request.get_json(silent=True) or {}
    name = str(payload.get("name") or "").strip()
    slug = str(payload.get("slug") or "").strip().lower() or _slugify(name)
    if not name:
        return jsonify({"error": "a project name is required"}), 400
    if not _SLUG.match(slug):
        return jsonify({"error": f"{slug!r} is not a usable short name — use "
                                 f"letters, numbers, and hyphens"}), 400

    conn = get_db()
    existing = conn.execute("SELECT slug, name FROM projects WHERE slug = ?",
                            (slug,)).fetchone()
    if existing:
        return jsonify({"error": f"a project with the short name {slug!r} "
                                 f"already exists ({existing['name']})"}), 409

    from ..ingest.store import upsert_project
    project_id = upsert_project(conn, slug, name)
    conn.commit()
    return jsonify({"id": project_id, "slug": slug, "name": name,
                    "run_count": 0}), 201


@api.get("/projects/<slug>/stats")
def project_stats_route(slug: str):
    """What a project holds. The UI shows this before asking to confirm a delete."""
    from ..ingest.store import project_stats

    conn = get_db()
    row = conn.execute("SELECT id, slug, name FROM projects WHERE slug = ?",
                       (slug,)).fetchone()
    if not row:
        return jsonify({"error": f"no project named {slug!r}"}), 404
    return jsonify({"project": dict(row), "stats": project_stats(conn, row["id"])})


@api.delete("/projects/<slug>")
def delete_project_route(slug: str):
    """Delete a project and all of its scans.

    The confirmation is checked here, not only in the browser. A client-side
    `confirm()` is a courtesy; the server is what actually stands between a
    mis-typed URL and an irreversible delete.
    """
    from ..ingest.store import delete_project

    payload = request.get_json(silent=True) or {}
    conn = get_db()
    row = conn.execute("SELECT id, slug, name FROM projects WHERE slug = ?",
                       (slug,)).fetchone()
    if not row:
        return jsonify({"error": f"no project named {slug!r}"}), 404
    if str(payload.get("confirm") or "") != slug:
        return jsonify({"error": f"to delete this project, send confirm={slug!r}"
                        }), 400

    stats = delete_project(conn, row["id"], raw_dir=get_config().raw_dir)
    return jsonify({"deleted": dict(row), "removed": stats})


@api.delete("/runs/<int:run_id>")
def delete_run_route(run_id: int):
    """Delete one run.

    Later runs keep their stored diffs, which were computed against this one. That
    is deliberate — recomputing them would silently rewrite history the user has
    already read. `frogscope reindex` rebuilds them on request.
    """
    from ..ingest.store import delete_run

    payload = request.get_json(silent=True) or {}
    conn = get_db()
    row = conn.execute(
        "SELECT r.id, r.run_key, r.label, p.slug AS project_slug "
        "FROM runs r JOIN projects p ON p.id = r.project_id WHERE r.id = ?",
        (run_id,)).fetchone()
    if not row:
        return jsonify({"error": f"no run with id {run_id}"}), 404
    if str(payload.get("confirm") or "") != row["run_key"]:
        return jsonify({"error": "to delete this run, send confirm with its "
                                 "run key"}), 400

    archive = get_config().raw_dir / f"{row['run_key']}.csv.gz"
    archive.unlink(missing_ok=True)
    delete_run(conn, run_id)
    conn.commit()
    return jsonify({"deleted": dict(row),
                    "note": "stored diffs on later runs were left as they were — "
                            "run `frogscope reindex` to rebuild them"})


RESET_PHRASE = "DELETE EVERYTHING"


@api.post("/reset")
def reset_route():
    """Empty the whole store.

    Requires a typed phrase rather than a boolean. A stray `{"confirm": true}`
    from a copied snippet should not be able to wipe an estate's scan history.
    """
    from ..ingest.store import reset_all

    payload = request.get_json(silent=True) or {}
    if str(payload.get("confirm") or "") != RESET_PHRASE:
        return jsonify({"error": f"to empty the store, send "
                                 f"confirm={RESET_PHRASE!r}"}), 400
    counts = reset_all(get_db(), raw_dir=get_config().raw_dir)
    return jsonify({"reset": True, "removed": counts})


@api.get("/runs")
def runs():
    conn = get_db()
    project = request.args.get("project")
    sql = (
        "SELECT r.*, p.slug AS project_slug, p.name AS project_name "
        "FROM runs r JOIN projects p ON p.id = r.project_id"
    )
    params: list = []
    if project:
        sql += " WHERE p.slug = ?"
        params.append(project)
    sql += " ORDER BY COALESCE(r.started_at,'') DESC, r.id DESC"
    return jsonify({"runs": [_row_to_dict(r) for r in conn.execute(sql, params)]})



# ── Scanning ────────────────────────────────────────────────────────────────
#
# The only endpoints that cause traffic to leave this machine. Everything else
# analyses a file. Scans run in a background thread and are tracked in memory —
# a server restart loses an in-flight scan, and the UI says so rather than
# leaving a progress bar stuck forever.

_SCANS: dict[str, dict[str, Any]] = {}
_SCANS_LOCK = threading.Lock()
# Shared with the scheduler (v2, scan/scheduler.py) — a scheduled run and a
# manual one must never execute at the same time, so both acquire the same
# semaphore rather than two separate ones. Imported, not redefined here.
_SCAN_SLOT = executor.SCAN_SLOT


@api.get("/scan/tools")
def scan_tools():
    """Whether the scanners are present, and how to get them if not.

    `ready` reflects CORE tools only (subfinder/httpx) — dnsx/mapcidr/tlsx
    power DNS/network analysis and TLS certificate reading, both of which
    run unconditionally now but degrade gracefully (a skip_reason on their
    own sidecar collector) if absent, so a machine missing them can still
    run a plain scan. Requiring all five here would make `ready` false on
    any install that never set those up, which is not what it means.
    """
    from ..scan import catalogue, inventory, tools as scan_tools_mod

    found = inventory()
    return jsonify({
        "tools": {name: tool.as_dict() for name, tool in found.items()},
        "ready": all(found[name].available for name in scan_tools_mod.CORE),
        "options": catalogue(),
    })


@api.post("/scan")
def scan_start():
    from ..scan import OptionError, parse

    payload = request.get_json(silent=True) or {}
    project = str(payload.get("project") or "").strip()
    if not project:
        return jsonify({"error": "choose a project for the scan first"}), 400

    conn = get_db()
    row = conn.execute("SELECT slug FROM projects WHERE slug = ?",
                       (project,)).fetchone()
    if not row:
        return jsonify({"error": f"no project named {project!r}"}), 404

    try:
        options = parse(payload)
    except OptionError as exc:
        return jsonify({"error": str(exc)}), 400

    with _SCANS_LOCK:
        running = [job for job in _SCANS.values() if job["state"] == "running"]
    if running:
        return jsonify({
            "error": "a scan is already running. Wait for it to finish or cancel "
                     "it — two scans at once would both be rate-limited against "
                     "the same estate.",
            "job_id": running[0]["job_id"],
        }), 409

    job_id = uuid.uuid4().hex[:12]
    label = str(payload.get("label") or "").strip() or None
    cfg = get_config()
    started_at = datetime.now(UTC).replace(microsecond=0).isoformat()

    with _SCANS_LOCK:
        _SCANS[job_id] = {
            "job_id": job_id, "state": "running", "project": project,
            "options": options.as_dict(), "progress": {}, "run": None,
            "error": None,
        }

    def worker() -> None:
        from ..scan import Cancelled, EmptyResult, ScanError, ScanRun
        from ..scan.runner import NeedsApproval

        def publish(progress) -> None:
            with _SCANS_LOCK:
                if job_id in _SCANS:
                    _SCANS[job_id]["progress"] = progress.as_dict()

        run = ScanRun(options, on_progress=publish)
        with _SCANS_LOCK:
            _SCANS[job_id]["_run"] = run

        acquired = _SCAN_SLOT.acquire(timeout=1)
        if not acquired:
            with _SCANS_LOCK:
                _SCANS[job_id].update(state="error",
                                      error="another scan holds the slot")
            return
        try:
            csv_path = run.run()
            publish(run.progress)

            with _SCANS_LOCK:
                _SCANS[job_id]["state"] = "ingesting"
                _SCANS[job_id]["progress"]["phase"] = "ingesting"
                _SCANS[job_id]["progress"]["message"] = (
                    "Analysing the results and comparing with previous scans")

            result = executor.ingest_scan_result(
                cfg, csv_path, options, run, started_at, project=project,
                label=label)

            with _SCANS_LOCK:
                _SCANS[job_id].update(state="done", run={
                    "run_id": result.run_id, "run_key": result.run_key,
                    "endpoint_count": result.endpoint_count,
                    "host_count": result.host_count,
                    "row_count": result.row_count,
                    "summary": result.summary,
                    "warnings": result.warnings,
                })
        except NeedsApproval as pause:
            # Enumeration is done and cost nobody anything. Probing is the part
            # that sends traffic, so the decision waits here — with the real number
            # in front of the user rather than a guess typed beforehand.
            with _SCANS_LOCK:
                _SCANS[job_id].update(
                    state="awaiting_approval",
                    hosts_found=len(pause.hosts),
                    host_sample=sorted(pause.hosts)[:25],
                    error=None)
        except Cancelled:
            with _SCANS_LOCK:
                _SCANS[job_id].update(state="cancelled",
                                      error="cancelled before it finished")
        except EmptyResult as exc:
            # Not a failure — the target genuinely had nothing to probe or
            # nothing answered. A distinct state so the UI can say so calmly
            # instead of showing the same red "scan failed" a crashed
            # subprocess gets.
            with _SCANS_LOCK:
                _SCANS[job_id].update(state="empty", error=str(exc))
        except (ScanError, pipeline.IncompleteScan, pipeline.DuplicateRun) as exc:
            with _SCANS_LOCK:
                _SCANS[job_id].update(state="error", error=str(exc))
        except Exception as exc:  # surfaced, never swallowed
            with _SCANS_LOCK:
                _SCANS[job_id].update(state="error",
                                      error=f"{type(exc).__name__}: {exc}")
        finally:
            _SCAN_SLOT.release()
            with _SCANS_LOCK:
                _SCANS.get(job_id, {}).pop("_run", None)

    threading.Thread(target=worker, daemon=True).start()
    return jsonify({"job_id": job_id, "state": "running"}), 202


@api.get("/scan/<job_id>")
def scan_status(job_id: str):
    with _SCANS_LOCK:
        job = _SCANS.get(job_id)
        if job is None:
            return jsonify({"error": "unknown scan"}), 404
        return jsonify({k: v for k, v in job.items() if not k.startswith("_")})


@api.post("/scan/<job_id>/cancel")
def scan_cancel(job_id: str):
    with _SCANS_LOCK:
        job = _SCANS.get(job_id)
        if job is None:
            return jsonify({"error": "unknown scan"}), 404
        run = job.get("_run")
    if run is None:
        return jsonify({"error": "that scan is not running"}), 409
    run.cancel()
    return jsonify({"cancelling": True})


@api.post("/scan/<job_id>/approve")
def scan_approve(job_id: str):
    """Continue a scan that paused to ask about its size."""
    with _SCANS_LOCK:
        job = _SCANS.get(job_id)
        if job is None:
            return jsonify({"error": "unknown scan"}), 404
        if job["state"] != "awaiting_approval":
            return jsonify({"error": "that scan is not waiting for approval"}), 409
        payload = dict(job["options"])
        hosts = int(job.get("hosts_found") or 0)
        project = job["project"]

    # Re-enumerate rather than trusting a host list round-tripped through the
    # browser: a client-supplied target list would be exactly the injection path
    # the option validator exists to close.
    payload["approved_hosts"] = hosts
    payload["project"] = project
    with _SCANS_LOCK:
        _SCANS[job_id]["state"] = "superseded"

    with current_app.test_request_context(json=payload):
        return scan_start()


@api.get("/scan")
def scan_list():
    """Recent scans, so a reloaded page can find one still in flight."""
    with _SCANS_LOCK:
        jobs = [{k: v for k, v in job.items() if not k.startswith("_")}
                for job in _SCANS.values()]
    return jsonify({"scans": jobs})


# ── Scheduled scanning (v2) ──────────────────────────────────────────────────
#
# A schedule stores the exact same options shape a manual scan builds
# (target_kind/targets/profile/flags/correlate) plus timing and an
# unattended-approval cap — scan/scheduler.py hands it to the identical
# executor.py path a manual scan uses, so a scheduled run and one triggered
# from this API are indistinguishable once ingested.

_PRESETS = ("hourly", "daily", "weekly")


def _schedule_row_to_dict(row) -> dict:
    out = dict(row)
    for key in ("targets_json", "flags_json", "correlate_json"):
        try:
            out[key.removesuffix("_json")] = json.loads(out.pop(key) or "null")
        except json.JSONDecodeError:
            out[key.removesuffix("_json")] = None
    return out


@api.get("/schedules")
def list_all_schedules_route():
    """Every schedule across every project — backs both the "Schedules"
    summary tab and the new-schedule form's collision check, neither of
    which cares about one project at a time."""
    from ..ingest.store import list_all_schedules

    conn = get_db()
    rows = list_all_schedules(conn)
    return jsonify({"schedules": [_schedule_row_to_dict(r) for r in rows]})


@api.get("/projects/<slug>/schedules")
def list_schedules_route(slug: str):
    from ..ingest.store import list_schedules

    conn = get_db()
    project = conn.execute("SELECT id FROM projects WHERE slug = ?",
                           (slug,)).fetchone()
    if not project:
        return jsonify({"error": f"no project named {slug!r}"}), 404
    rows = list_schedules(conn, project["id"])
    return jsonify({"schedules": [_schedule_row_to_dict(r) for r in rows]})


@api.post("/projects/<slug>/schedules")
def create_schedule_route(slug: str):
    from ..ingest.store import get_schedule, insert_schedule
    from ..scan import OptionError
    from ..scan import options as scan_options
    from ..scan.scheduler import next_run_at

    conn = get_db()
    project = conn.execute("SELECT id FROM projects WHERE slug = ?",
                           (slug,)).fetchone()
    if not project:
        return jsonify({"error": f"no project named {slug!r}"}), 404

    payload = request.get_json(silent=True) or {}
    name = str(payload.get("name") or "").strip()
    if not name:
        return jsonify({"error": "name this schedule"}), 400
    if not payload.get("authorised"):
        return jsonify({
            "error": "confirm you are authorised to scan these targets — "
                     "every unattended run this schedule triggers sends real "
                     "traffic to real infrastructure",
        }), 400

    preset = str(payload.get("preset") or "daily")
    if preset not in _PRESETS:
        return jsonify({"error": f"preset must be one of {_PRESETS}"}), 400

    # No per-schedule approval cap — an unattended run auto-approves
    # everything it finds, same as a manual scan does once past the
    # awaiting-approval pause. `MAX_HOSTS` (options.py) is still the one
    # real, unconditional stop against a genuinely runaway target list; it
    # is not user-configurable and applies here exactly as it does to every
    # other scan.
    max_hosts_cap = scan_options.MAX_HOSTS

    # Validated the same way a manual scan is, so a bad target list is
    # rejected here — when a human is looking at the form — rather than
    # only discovered the first time the schedule fires unattended.
    try:
        scan_options.parse({
            "targets": payload.get("targets") or [],
            "profile": payload.get("profile"),
            "authorised": True,
        })
    except OptionError as exc:
        return jsonify({"error": str(exc)}), 400

    targets = payload.get("targets") or []
    kinds = {scan_options.classify_target(str(t))[0] for t in targets if str(t).strip()}
    target_kind = next(iter(kinds)) if len(kinds) == 1 else "mixed"

    day_of_week = payload.get("day_of_week")
    schedule_id = insert_schedule(conn, project["id"], {
        "name": name,
        "target_kind": target_kind,
        "targets_json": json.dumps(targets),
        "profile": payload.get("profile") or scan_options.DEFAULT_PROFILE,
        # DNS/network/TLS analysis and every httpx collection flag are all
        # unconditional now — nothing sends `flags`/`correlate_steps`
        # anymore. Both columns stay in the schema (harmless, unused) rather
        # than a migration to drop them; see `scan/scheduler.py`.
        "flags_json": "{}",
        "correlate_json": "{}",
        "subfinder": payload.get("subfinder", True),
        "preset": preset,
        "time_of_day": payload.get("time_of_day"),
        "day_of_week": int(day_of_week) if day_of_week is not None else None,
        "max_hosts_cap": max_hosts_cap,
        "enabled": payload.get("enabled", True),
        "next_run_at": next_run_at(preset, payload.get("time_of_day"), day_of_week),
    })
    conn.commit()
    row = get_schedule(conn, schedule_id)
    return jsonify({"schedule": _schedule_row_to_dict(row)}), 201


@api.route("/schedules/<int:schedule_id>", methods=["PATCH", "DELETE"])
def modify_schedule_route(schedule_id: int):
    from ..ingest.store import delete_schedule, get_schedule, update_schedule

    conn = get_db()
    existing = get_schedule(conn, schedule_id)
    if not existing:
        return jsonify({"error": f"no schedule with id {schedule_id}"}), 404

    if request.method == "DELETE":
        delete_schedule(conn, schedule_id)
        conn.commit()
        return jsonify({"deleted": True})

    from ..scan.scheduler import next_run_at

    payload = request.get_json(silent=True) or {}
    fields: dict[str, Any] = {}
    if "name" in payload:
        fields["name"] = str(payload["name"]).strip()
    if "enabled" in payload:
        fields["enabled"] = int(bool(payload["enabled"]))
    if "preset" in payload or "time_of_day" in payload or "day_of_week" in payload:
        preset = payload.get("preset", existing["preset"])
        time_of_day = payload.get("time_of_day", existing["time_of_day"])
        day_of_week = payload.get("day_of_week", existing["day_of_week"])
        if preset not in _PRESETS:
            return jsonify({"error": f"preset must be one of {_PRESETS}"}), 400
        fields["preset"] = preset
        fields["time_of_day"] = time_of_day
        fields["day_of_week"] = day_of_week
        fields["next_run_at"] = next_run_at(preset, time_of_day, day_of_week)

    update_schedule(conn, schedule_id, fields)
    conn.commit()
    row = get_schedule(conn, schedule_id)
    return jsonify({"schedule": _schedule_row_to_dict(row)})


@api.post("/schedules/<int:schedule_id>/run-now")
def run_schedule_now_route(schedule_id: int):
    """Fire one schedule immediately, out of cadence — same execution path
    the scheduler's own tick uses, just triggered by a click instead of the
    clock. Runs inline (this can take minutes), matching how a manual scan
    already ties up the request only up to job creation — this route is
    synchronous by contrast, so the UI should show it as a blocking action."""
    from ..ingest.store import get_schedule
    from ..scan.scheduler import Scheduler

    conn = get_db()
    row = get_schedule(conn, schedule_id)
    if not row:
        return jsonify({"error": f"no schedule with id {schedule_id}"}), 404

    project = conn.execute("SELECT slug FROM projects WHERE id = ?",
                           (row["project_id"],)).fetchone()
    scheduler = Scheduler(get_config())
    scheduler._run_one(conn, {**dict(row), "project_slug": project["slug"]})
    conn.commit()

    refreshed = get_schedule(conn, schedule_id)
    return jsonify({"schedule": _schedule_row_to_dict(refreshed)})


@api.get("/quality")
def data_quality():
    conn = get_db()
    run = resolve_run(conn, request.args.get("run"), request.args.get("project"))
    if not run:
        return jsonify({"error": "no runs ingested yet"}), 404

    census = [
        dict(r) for r in conn.execute(
            "SELECT column_name, non_empty, total, fill_pct, sample "
            "FROM run_columns WHERE run_id = ? ORDER BY fill_pct DESC, column_name",
            (run["id"],),
        )
    ]
    inconsistent = conn.execute(
        "SELECT COUNT(*) AS n FROM endpoints "
        "WHERE run_id = ? AND intra_run_inconsistent = 1",
        (run["id"],),
    ).fetchone()["n"]
    collapsed = conn.execute(
        "SELECT COUNT(*) AS n, COALESCE(SUM(probe_count - 1), 0) AS extra "
        "FROM endpoints WHERE run_id = ? AND probe_count > 1",
        (run["id"],),
    ).fetchone()

    return jsonify({
        "run": _row_to_dict(run),
        "columns": census,
        "empty_columns": [c["column_name"] for c in census if c["fill_pct"] == 0.0],
        "collapsed_groups": collapsed["n"],
        "collapsed_extra_rows": collapsed["extra"],
        "inconsistent_endpoints": inconsistent,
        "suggestions": quality.suggest_httpx_flags(census),
        "recommended_command": quality.recommended_command(census),
    })


# ── Endpoints grid ──────────────────────────────────────────────────────────

def _query_args() -> dict[str, Any]:
    if request.method == "POST":
        body = request.get_json(silent=True) or {}
    else:
        body = {}
        if request.args.get("filters"):
            try:
                body["filters"] = json.loads(request.args["filters"])
            except json.JSONDecodeError:
                raise FilterError("filters must be valid JSON")
    return {
        "filters": body.get("filters") or {},
        "search": body.get("search") or request.args.get("q") or "",
        "sort": body.get("sort") or request.args.get("sort"),
        "page": int(body.get("page") or request.args.get("page") or 1),
        "page_size": int(body.get("page_size") or request.args.get("page_size") or 100),
        "columns": body.get("columns"),
        "run": body.get("run") or request.args.get("run"),
        "project": body.get("project") or request.args.get("project"),
        "with_facets": bool(body.get("with_facets", True)),
    }


@api.route("/endpoints/query", methods=["GET", "POST"])
def endpoints_query():
    conn, catalog = get_db(), get_catalog()
    args = _query_args()
    run = resolve_run(conn, args["run"], args["project"])
    if not run:
        return jsonify({"error": "no runs ingested yet", "rows": [], "total": 0}), 404

    result = facets.query_endpoints(
        conn, run["id"], catalog,
        filters=args["filters"], search=args["search"], sort=args["sort"],
        page=args["page"], page_size=args["page_size"], columns=args["columns"],
    )
    result["run"] = _row_to_dict(run)
    if args["with_facets"]:
        result["facets"] = facets.compute(
            conn, run["id"], catalog, args["filters"], args["search"]
        )
    return jsonify(result)


@api.route("/endpoints/facets", methods=["GET", "POST"])
def endpoints_facets():
    conn, catalog = get_db(), get_catalog()
    args = _query_args()
    run = resolve_run(conn, args["run"], args["project"])
    if not run:
        return jsonify({"facets": {}}), 404
    return jsonify({
        "facets": facets.compute(
            conn, run["id"], catalog, args["filters"], args["search"],
            fields=(request.get_json(silent=True) or {}).get("fields"),
        )
    })


@api.get("/endpoints/<path:endpoint_key>")
def endpoint_detail(endpoint_key: str):
    conn = get_db()
    run = resolve_run(conn, request.args.get("run"), request.args.get("project"))
    if not run:
        return jsonify({"error": "no runs ingested yet"}), 404

    row = conn.execute(
        "SELECT * FROM endpoints WHERE run_id = ? AND endpoint_key = ?",
        (run["id"], endpoint_key),
    ).fetchone()
    if not row:
        return jsonify({"error": f"endpoint not found: {endpoint_key}"}), 404

    record = dict(row)
    for key in ("lists_json", "raw_json", "extra_json", "inconsistent_fields"):
        if record.get(key):
            try:
                record[key.removesuffix("_json")] = json.loads(record[key])
            except json.JSONDecodeError:
                pass

    siblings = [
        dict(r) for r in conn.execute(
            "SELECT endpoint_key, port, scheme, status_code, response_class, title "
            "FROM endpoints WHERE run_id = ? AND host = ? AND endpoint_key != ? "
            "ORDER BY port",
            (run["id"], row["host"], endpoint_key),
        )
    ]
    neighbours = []
    if row["host_ip"]:
        neighbours = [
            dict(r) for r in conn.execute(
                "SELECT DISTINCT host FROM endpoints "
                "WHERE run_id = ? AND host_ip = ? AND host != ? LIMIT 50",
                (run["id"], row["host_ip"], row["host"]),
            )
        ]

    # v2: richer detail for the drawer, no new fetch — same_ip above is
    # host-only; this adds the IP's own correlation record plus the
    # certificate this endpoint presents, if any.
    network = None
    if row["host_ip"]:
        ip_row = conn.execute(
            "SELECT * FROM ip_addresses WHERE run_id = ? AND ip = ?",
            (run["id"], row["host_ip"]),
        ).fetchone()
        if ip_row:
            network = dict(ip_row)
            if network.get("ptr_json"):
                try:
                    network["ptr"] = json.loads(network.pop("ptr_json"))
                except json.JSONDecodeError:
                    network.pop("ptr_json", None)

    cert = None
    same_cert: list[dict] = []
    if record.get("cert_sha256"):
        cert_row = conn.execute(
            "SELECT * FROM certificates WHERE run_id = ? AND cert_sha256 = ?",
            (run["id"], record["cert_sha256"]),
        ).fetchone()
        if cert_row:
            cert = dict(cert_row)
            cert.pop("raw_json", None)
        same_cert = [
            dict(r) for r in conn.execute(
                "SELECT DISTINCT host, port FROM cert_observations "
                "WHERE run_id = ? AND cert_sha256 = ? AND host != ? "
                "ORDER BY host, port LIMIT 50",
                (run["id"], record["cert_sha256"], row["host"]))
        ]

    return jsonify({
        "endpoint": record,
        "same_host": siblings,
        "same_ip": neighbours,
        "network": network,
        "cert": cert,
        "same_cert": same_cert,
        "run": _row_to_dict(run),
    })


@api.route("/endpoints/export", methods=["GET", "POST"])
def endpoints_export():
    """Export the *filtered* set, not just the current page."""
    import csv
    import io

    conn, catalog = get_db(), get_catalog()
    args = _query_args()
    run = resolve_run(conn, args["run"], args["project"])
    if not run:
        return jsonify({"error": "no runs ingested yet"}), 404

    columns = args["columns"] or catalog.default_visible()
    columns = [c for c in columns if c in catalog]
    fmt = (request.args.get("format") or "csv").lower()

    result = facets.query_endpoints(
        conn, run["id"], catalog,
        filters=args["filters"], search=args["search"], sort=args["sort"],
        page=1, page_size=100000, columns=columns,
    )
    rows = result["rows"]

    if fmt == "json":
        return Response(
            json.dumps(rows, indent=2, default=str),
            mimetype="application/json",
            headers={"Content-Disposition":
                     f'attachment; filename="{run["run_key"]}.json"'},
        )

    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=columns, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow({
            c: ("|".join(str(x) for x in row[c])
                if isinstance(row.get(c), list) else row.get(c, ""))
            for c in columns
        })
    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition":
                 f'attachment; filename="{run["run_key"]}.csv"'},
    )


@api.get("/hosts")
def hosts():
    conn = get_db()
    run = resolve_run(conn, request.args.get("run"), request.args.get("project"))
    if not run:
        return jsonify({"hosts": []}), 404
    rows = []
    for row in conn.execute(
        "SELECT * FROM host_rollup WHERE run_id = ? ORDER BY host", (run["id"],)
    ):
        record = dict(row)
        for key in ("ports_json", "ip_json", "cname_json", "tech_json"):
            if record.get(key):
                try:
                    record[key.removesuffix("_json")] = json.loads(record[key])
                except json.JSONDecodeError:
                    pass
                record.pop(key, None)
        rows.append(record)
    return jsonify({"hosts": rows, "run": _row_to_dict(run)})


@api.get("/summary")
def summary():
    conn = get_db()
    run = resolve_run(conn, request.args.get("run"), request.args.get("project"))
    if not run:
        return jsonify({"error": "no runs ingested yet"}), 404
    return jsonify({
        "run": _row_to_dict(run),
        "summary": json.loads(run["summary_json"] or "{}"),
    })


# ── Upload ──────────────────────────────────────────────────────────────────

@api.post("/ingest")
def ingest_upload():
    upload = request.files.get("file")
    if upload is None or not upload.filename:
        return jsonify({"error": "no file uploaded"}), 400

    project = request.form.get("project") or "default"
    label = request.form.get("label") or Path(upload.filename).stem
    force = request.form.get("force") in ("1", "true", "on")
    allow_incomplete = request.form.get("allow_incomplete") in ("1", "true", "on")
    allow_drift = request.form.get("allow_drift") in ("1", "true", "on")

    tmp_dir = Path(tempfile.mkdtemp(prefix="frogscope-upload-"))
    tmp_path = tmp_dir / Path(upload.filename).name
    upload.save(tmp_path)

    job_id = uuid.uuid4().hex[:12]
    with _JOBS_LOCK:
        _JOBS[job_id] = {"state": "running", "step": "reading file", "filename": upload.filename}

    cfg = get_config()

    def worker() -> None:
        from ..db.connection import connect
        conn = connect(cfg.db_path)
        try:
            with _JOBS_LOCK:
                _JOBS[job_id]["step"] = "normalising and enriching"
            result = pipeline.ingest(
                conn, cfg, tmp_path, project=project, label=label,
                force=force, allow_incomplete=allow_incomplete,
                allow_drift=allow_drift,
                # The temp file was written by this request, so its mtime says
                # nothing about whether the scan had finished.
                trust_mtime=False,
            )
            with _JOBS_LOCK:
                _JOBS[job_id] = {
                    "state": "done",
                    "run_id": result.run_id,
                    "run_key": result.run_key,
                    "endpoint_count": result.endpoint_count,
                    "host_count": result.host_count,
                    "row_count": result.row_count,
                    "collapse": result.collapse,
                    "warnings": result.warnings,
                    "summary": result.summary,
                }
        except pipeline.DuplicateRun as exc:
            with _JOBS_LOCK:
                _JOBS[job_id] = {
                    "state": "duplicate",
                    "message": str(exc),
                    "run_id": exc.existing["run_id"],
                    # Named here too, so the UI never has to infer which override
                    # applies from the state string.
                    "override": "force",
                }
        except pipeline.IncompleteScan as exc:
            with _JOBS_LOCK:
                _JOBS[job_id] = {
                    "state": "incomplete",
                    "message": str(exc),
                    "warnings": exc.warnings,
                    # WHICH override ungates this. A truncated-looking file and a
                    # suspicious change in scale both land here but need different
                    # flags, and offering the wrong one gives the user a button
                    # that can never succeed.
                    "override": exc.override,
                }
        except Exception as exc:  # surfaced to the UI rather than swallowed
            with _JOBS_LOCK:
                _JOBS[job_id] = {"state": "error", "message": f"{type(exc).__name__}: {exc}"}
        finally:
            conn.close()

    threading.Thread(target=worker, daemon=True).start()
    return jsonify({"job_id": job_id, "state": "running"}), 202


@api.get("/ingest/<job_id>")
def ingest_status(job_id: str):
    with _JOBS_LOCK:
        job = _JOBS.get(job_id)
    if job is None:
        return jsonify({"error": "unknown job"}), 404
    return jsonify(job)


# ── Phase 2: findings, rules, risk ──────────────────────────────────────────

SEVERITY_SORT = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _ruleset():
    cfg = get_config()
    from ..scoring.rules import load_ruleset
    key = "FROGSCOPE_RULESET"
    from flask import current_app
    if key not in current_app.config:
        current_app.config[key] = load_ruleset(cfg.config_dir)
    return current_app.config[key]


@api.get("/rules")
def rules():
    """The rule set, so the UI can show a rule's own definition beside its
    findings rather than asking the reader to trust a number."""
    from ..scoring.rules import describe_template

    ruleset = _ruleset()
    payload = ruleset.as_dict()

    # These are DEFINITIONS, with no endpoint to fill them, so a raw
    # `{vuln_summary}` would read as a broken template. Placeholders become what
    # they stand for; a scored finding still substitutes the observed value.
    for rule in payload["rules"]:
        for field in ("why", "remediation", "exec_line", "title"):
            if rule.get(field):
                rule[field] = describe_template(rule[field])

    conn = get_db()
    run = resolve_run(conn, request.args.get("run"), request.args.get("project"))
    if run:
        fired = {
            r["rule_id"]: r["n"] for r in conn.execute(
                "SELECT rule_id, COUNT(*) n FROM findings "
                "WHERE last_seen_run_id = ? GROUP BY 1", (run["id"],))
        }
        total = conn.execute(
            "SELECT COUNT(*) n FROM asset_scores WHERE run_id = ? AND excluded = 0",
            (run["id"],)).fetchone()["n"]
        for rule in payload["rules"]:
            rule["fired_on_hosts"] = fired.get(rule["id"], 0)
        payload["scored_endpoints"] = total
        payload["run"] = _row_to_dict(run)
    return jsonify(payload)


@api.get("/findings")
def findings():
    conn = get_db()
    sql = (
        "SELECT f.*, p.slug AS project_slug FROM findings f "
        "JOIN projects p ON p.id = f.project_id WHERE 1=1"
    )
    params: list = []
    if request.args.get("project"):
        sql += " AND p.slug = ?"
        params.append(request.args["project"])
    for field, column in (("severity", "f.severity"), ("status", "f.status"),
                          ("rule", "f.rule_id"), ("host", "f.asset_key")):
        values = request.args.getlist(field)
        if values:
            placeholders = ",".join("?" for _ in values)
            sql += f" AND {column} IN ({placeholders})"
            params.extend(values)

    rows = []
    for row in conn.execute(sql, params):
        record = dict(row)
        try:
            record["detail"] = json.loads(record.pop("detail_json") or "{}")
        except json.JSONDecodeError:
            record["detail"] = {}
        rows.append(record)

    rows.sort(key=lambda r: (SEVERITY_SORT.get(r["severity"], 9),
                             -(r["detail"].get("max_score") or 0), r["rule_id"]))

    ruleset = _ruleset()
    rule_index = {r.id: r.as_dict() for r in ruleset.rules}
    by_rule: dict[str, dict] = {}
    for record in rows:
        group = by_rule.setdefault(record["rule_id"], {
            "rule_id": record["rule_id"],
            "rule": rule_index.get(record["rule_id"]),
            "severity": record["severity"],
            "confidence": record["confidence"],
            "title": record["title"],
            "findings": [],
            "host_count": 0,
            "endpoint_count": 0,
            "max_score": 0,
        })
        group["findings"].append(record)
        group["host_count"] += 1
        group["endpoint_count"] += record["detail"].get("endpoint_count", 0)
        group["max_score"] = max(group["max_score"],
                                 record["detail"].get("max_score") or 0)

    grouped = sorted(
        by_rule.values(),
        key=lambda g: (SEVERITY_SORT.get(g["severity"], 9), -g["host_count"]),
    )

    counts: dict[str, int] = {}
    for record in rows:
        counts[record["severity"]] = counts.get(record["severity"], 0) + 1

    return jsonify({
        "findings": rows,
        "grouped": grouped,
        "total": len(rows),
        "by_severity": {
            k: counts[k] for k in ("critical", "high", "medium", "low", "info")
            if k in counts
        },
        "open": sum(1 for r in rows if r["status"] == "open"),
        "resolved": sum(1 for r in rows if r["status"] == "resolved"),
        "acknowledged": sum(1 for r in rows if r["status"] == "ack"),
    })


@api.post("/findings/<int:finding_id>/status")
def set_finding_status(finding_id: int):
    body = request.get_json(silent=True) or {}
    status = body.get("status")
    if status not in ("open", "ack", "resolved"):
        return jsonify({"error": "status must be open, ack, or resolved"}), 400

    from ..ingest.store import now_iso
    conn = get_db()
    row = conn.execute("SELECT id FROM findings WHERE id = ?", (finding_id,)).fetchone()
    if row is None:
        return jsonify({"error": "finding not found"}), 404

    conn.execute(
        "UPDATE findings SET status = ?, ack_by = ?, ack_note = ?, ack_at = ?, "
        "updated_at = ? WHERE id = ?",
        (status, body.get("by") or "local", body.get("note"),
         now_iso() if status == "ack" else None, now_iso(), finding_id),
    )
    conn.commit()
    return jsonify({"ok": True, "status": status})


@api.get("/score/<path:endpoint_key>")
def score_detail(endpoint_key: str):
    """The full trace behind one endpoint's score."""
    conn = get_db()
    run = resolve_run(conn, request.args.get("run"), request.args.get("project"))
    if not run:
        return jsonify({"error": "no runs ingested yet"}), 404

    row = conn.execute(
        "SELECT * FROM asset_scores WHERE run_id = ? AND endpoint_key = ?",
        (run["id"], endpoint_key),
    ).fetchone()
    if row is None:
        return jsonify({"error": f"no score for {endpoint_key}"}), 404

    record = dict(row)
    for key in ("contributions_json", "modifiers_json", "skipped_json"):
        try:
            record[key.removesuffix("_json")] = json.loads(record.pop(key) or "[]")
        except json.JSONDecodeError:
            record[key.removesuffix("_json")] = []

    ruleset = _ruleset()
    record["buckets_meta"] = ruleset.buckets
    record["bands"] = ruleset.bands
    return jsonify(record)


@api.get("/risk")
def risk_summary():
    """Headline risk numbers for the overview."""
    conn = get_db()
    run = resolve_run(conn, request.args.get("run"), request.args.get("project"))
    if not run:
        return jsonify({"error": "no runs ingested yet"}), 404

    try:
        stored = json.loads(run["risk_summary_json"] or "{}")
    except (json.JSONDecodeError, IndexError, KeyError):
        stored = {}

    bands = {
        r["band"]: r["n"] for r in conn.execute(
            "SELECT band, COUNT(*) n FROM asset_scores WHERE run_id = ? "
            "AND excluded = 0 GROUP BY 1", (run["id"],))
    }
    worst = {
        r["worst_severity"]: r["n"] for r in conn.execute(
            "SELECT worst_severity, COUNT(*) n FROM asset_scores WHERE run_id = ? "
            "AND excluded = 0 AND worst_severity != '' GROUP BY 1", (run["id"],))
    }
    top_hosts = [
        dict(r) for r in conn.execute(
            "SELECT host, host_display, risk_score, risk_band, finding_count, env, zone "
            "FROM host_rollup WHERE run_id = ? ORDER BY risk_score DESC LIMIT 10",
            (run["id"],))
    ]
    top_endpoints = [
        dict(r) for r in conn.execute(
            "SELECT endpoint_key, risk_score, risk_band, worst_severity, "
            "top_finding, finding_count FROM endpoints WHERE run_id = ? "
            "AND risk_excluded = 0 ORDER BY risk_score DESC LIMIT 10", (run["id"],))
    ]

    ruleset = _ruleset()
    order = ["critical", "high", "medium", "low", "info"]
    return jsonify({
        "run": _row_to_dict(run),
        "residual_risk": stored.get("residual_risk", {}),
        "by_band": {k: bands[k] for k in order if k in bands},
        "by_worst_severity": {k: worst[k] for k in order if k in worst},
        "findings": {
            "total": stored.get("total", 0),
            "by_severity": stored.get("by_severity", {}),
            "by_rule": stored.get("by_rule", {}),
            "affected_hosts": stored.get("affected_hosts", 0),
            "lifecycle": stored.get("finding_lifecycle", {}),
        },
        "skipped_rules": stored.get("skipped_rules", []),
        "top_hosts": top_hosts,
        "top_endpoints": top_endpoints,
        # sqlite3.Row has no .get(), so this cannot be simplified.
        "rules_hash": (run["rules_hash"]
                       if "rules_hash" in run.keys() else None),
        "bands": ruleset.bands,
        "buckets": ruleset.buckets,
    })


# ── Phase 3: executive view ─────────────────────────────────────────────────

@api.get("/exec")
def executive():
    """Everything the executive page needs, in one request.

    Assembled server-side so the numbers on the page and the sentences beside
    them cannot drift apart.
    """
    from ..analytics import kpis, narrative

    conn = get_db()
    run = resolve_run(conn, request.args.get("run"), request.args.get("project"))
    if not run:
        return jsonify({"error": "no runs ingested yet"}), 404

    payload = kpis.build(conn, run, _ruleset())
    payload["narrative"] = narrative.build(payload)
    return jsonify(payload)


# ── Phase 4: changes and trends ─────────────────────────────────────────────

@api.get("/changes")
def changes():
    """Field-level changes for a run, grouped by asset."""
    conn = get_db()
    run = resolve_run(conn, request.args.get("run"), request.args.get("project"))
    if not run:
        return jsonify({"error": "no runs ingested yet"}), 404

    include_noisy = request.args.get("noisy") in ("1", "true")
    kinds = request.args.getlist("type") or None
    severities = request.args.getlist("severity") or None

    sql = "SELECT * FROM changes WHERE run_id = ?"
    params: list = [run["id"]]
    if not include_noisy:
        sql += " AND is_noisy = 0"
    if kinds:
        sql += f" AND change_type IN ({','.join('?' for _ in kinds)})"
        params.extend(kinds)
    if severities:
        sql += f" AND severity IN ({','.join('?' for _ in severities)})"
        params.extend(severities)
    sql += " ORDER BY asset_key, field"

    rows = []
    for row in conn.execute(sql, params):
        record = dict(row)
        for key in ("before_json", "after_json", "added_json", "removed_json"):
            raw = record.pop(key, None)
            if raw:
                try:
                    record[key.removesuffix("_json")] = json.loads(raw)
                except json.JSONDecodeError:
                    record[key.removesuffix("_json")] = raw
        rows.append(record)

    # Group per asset so one endpoint with six changed fields reads as one entry.
    grouped: dict[str, dict] = {}
    for record in rows:
        entry = grouped.setdefault(record["asset_key"], {
            "asset_key": record["asset_key"],
            "host": record["host"],
            "change_type": record["change_type"],
            "fields": [],
            "worst_severity": "info",
            "direction": "lateral",
            "classification_only": True,
        })
        if record["field"]:
            entry["fields"].append(record)
        if not record["is_classification"]:
            entry["classification_only"] = False
            if SEVERITY_SORT.get(record["severity"], 9) < \
                    SEVERITY_SORT.get(entry["worst_severity"], 9):
                entry["worst_severity"] = record["severity"]
            if record["direction"] == "worse":
                entry["direction"] = "worse"
            elif record["direction"] == "better" and entry["direction"] != "worse":
                entry["direction"] = "better"

    order = {"added": 0, "returned": 1, "removed": 2, "modified": 3}
    assets = sorted(
        grouped.values(),
        key=lambda e: (order.get(e["change_type"], 9),
                       SEVERITY_SORT.get(e["worst_severity"], 9),
                       e["asset_key"]),
    )

    try:
        summary = json.loads(run["diff_json"] or "{}")
    except (json.JSONDecodeError, TypeError):
        summary = {}

    flapping = [
        dict(r) for r in conn.execute(
            "SELECT asset_key, presence, flap_count, stability, runs_seen "
            "FROM asset_presence WHERE project_id = ? AND asset_kind = 'endpoint' "
            "AND is_flapping = 1 ORDER BY flap_count DESC LIMIT 100",
            (run["project_id"],))
    ]

    prev = None
    if run["prev_run_id"]:
        prev_row = conn.execute("SELECT id, run_key, label, started_at FROM runs "
                                "WHERE id = ?", (run["prev_run_id"],)).fetchone()
        prev = dict(prev_row) if prev_row else None

    return jsonify({
        "run": _row_to_dict(run),
        "previous_run": prev,
        "summary": summary,
        "assets": assets,
        "total_changes": len(rows),
        "flapping": flapping,
        "rules_changed": bool(
            prev and run["rules_hash"] and prev_row
            and conn.execute("SELECT rules_hash FROM runs WHERE id = ?",
                             (run["prev_run_id"],)).fetchone()["rules_hash"]
            != run["rules_hash"]),
    })


@api.get("/diff")
def arbitrary_diff():
    """Compare any two runs on demand.

    Same function the ingest path uses, with persistence off — so "versus the
    January baseline" works, not only "versus last week".
    """
    from ..ingest import diff as diff_mod

    conn = get_db()
    cfg = get_config()
    to_run = resolve_run(conn, request.args.get("to"), request.args.get("project"))
    if not to_run:
        return jsonify({"error": "no runs ingested yet"}), 404

    which = request.args.get("from") or "prev"
    if which == "prev":
        from_id = diff_mod.previous_run_id(conn, to_run["project_id"], to_run["id"])
    elif which == "first":
        row = conn.execute(
            "SELECT id FROM runs WHERE project_id = ? AND duplicate_of IS NULL "
            "ORDER BY COALESCE(started_at,''), id LIMIT 1",
            (to_run["project_id"],)).fetchone()
        from_id = row["id"] if row else None
    else:
        from_row = resolve_run(conn, which, request.args.get("project"))
        from_id = from_row["id"] if from_row else None

    if from_id is None:
        return jsonify({
            "error": "nothing to compare against",
            "summary": {"baseline": True,
                        "note": "This is the earliest run for this project."},
        }), 200
    if from_id == to_run["id"]:
        return jsonify({"error": "cannot compare a run with itself"}), 400

    summary = diff_mod.diff_runs(conn, to_run["project_id"], to_run["id"],
                                 from_id, cfg.diff, persist=False)
    from_row = conn.execute("SELECT id, run_key, label, started_at FROM runs "
                            "WHERE id = ?", (from_id,)).fetchone()
    return jsonify({
        "from": dict(from_row) if from_row else None,
        "to": _row_to_dict(to_run),
        "summary": summary,
    })


@api.get("/trends")
def trends():
    from ..ingest import timeseries

    conn = get_db()
    project = request.args.get("project")
    if project:
        row = conn.execute("SELECT id FROM projects WHERE slug = ?",
                           (project,)).fetchone()
        project_id = row["id"] if row else None
    else:
        run = resolve_run(conn, None, None)
        project_id = run["project_id"] if run else None

    if project_id is None:
        return jsonify({"error": "no project found"}), 404

    metric = request.args.get("metric")
    dim = request.args.get("dim", "all")
    limit = int(request.args.get("limit", 24))

    if metric:
        return jsonify({
            "metric": metric, "dim": dim,
            "series": timeseries.series(conn, project_id, metric, dim, limit),
        })

    # Default bundle: the metrics the executive and trends pages need.
    headline = [
        "hosts", "real_endpoints", "hosts_needing_attention",
        "posture_index_host", "posture_index_endpoint", "findings_total",
        "findings_critical", "findings_high", "no_waf_hosts",
        "origin_exposed_hosts", "remote_access", "mgmt_surfaces",
        "eol_hosts", "takeover_candidates", "nonprod_exposed",
        "changes_added", "changes_removed", "changes_modified",
    ]
    labels = {
        m["key"]: m.get("label", m["key"])
        for m in (get_config().diff.get("metrics") or [])
    }
    out = {}
    for name in headline:
        points = timeseries.series(conn, project_id, name, "all", limit)
        if points:
            out[name] = {"label": labels.get(name, name.replace("_", " ")),
                         "points": points}

    runs = [
        dict(r) for r in conn.execute(
            "SELECT id, run_key, label, started_at, incomplete, rules_hash "
            "FROM runs WHERE project_id = ? AND duplicate_of IS NULL "
            "ORDER BY COALESCE(started_at,''), id", (project_id,))
    ]
    return jsonify({
        "runs": runs[-limit:],
        "metrics": out,
        "available": timeseries.available_metrics(conn, project_id),
        "enough_runs": len(runs) >= 2,
    })


@api.get("/history/<path:endpoint_key>")
def endpoint_history(endpoint_key: str):
    """When each attribute of one endpoint last changed."""
    conn = get_db()
    run = resolve_run(conn, request.args.get("run"), request.args.get("project"))
    if not run:
        return jsonify({"error": "no runs ingested yet"}), 404

    rows = [
        dict(r) for r in conn.execute(
            """SELECT h.field, h.run_id, h.value_json, h.changed_at,
                      r.run_key, r.label, r.started_at
                 FROM asset_attr_history h JOIN runs r ON r.id = h.run_id
                WHERE h.project_id = ? AND h.asset_key = ?
                ORDER BY COALESCE(r.started_at,''), h.field""",
            (run["project_id"], endpoint_key))
    ]
    for row in rows:
        try:
            row["value"] = json.loads(row.pop("value_json") or "null")
        except json.JSONDecodeError:
            row["value"] = row.pop("value_json", None)

    presence = conn.execute(
        "SELECT * FROM asset_presence WHERE project_id = ? AND asset_kind = "
        "'endpoint' AND asset_key = ?", (run["project_id"], endpoint_key)
    ).fetchone()

    scores = [
        dict(r) for r in conn.execute(
            """SELECT s.run_id, s.score, s.band, r.run_key, r.label, r.started_at
                 FROM asset_scores s JOIN runs r ON r.id = s.run_id
                WHERE s.endpoint_key = ? AND r.project_id = ?
                ORDER BY COALESCE(r.started_at,''), r.id""",
            (endpoint_key, run["project_id"]))
    ]

    return jsonify({
        "endpoint_key": endpoint_key,
        "changes": rows,
        "presence": dict(presence) if presence else None,
        "scores": scores,
    })


# ── v2: network & certificate correlation ───────────────────────────────────
#
# Empty (not absent) on any run that never opted into "Correlate assets" —
# the new tables simply have no rows for that run_id, so every route below
# degrades to an empty list/404 exactly like querying `endpoints` for a run
# that hasn't been ingested yet. No special-casing needed.

def _paginate(request) -> tuple[int, int]:
    page = max(1, int(request.args.get("page") or 1))
    page_size = min(500, max(1, int(request.args.get("page_size") or 100)))
    return page, page_size


@api.get("/network/summary")
def network_summary():
    conn = get_db()
    run = resolve_run(conn, request.args.get("run"), request.args.get("project"))
    if not run:
        return jsonify({"error": "no runs ingested yet"}), 404
    rid = run["id"]
    one = lambda sql: conn.execute(sql, (rid,)).fetchone()[0]  # noqa: E731
    collectors = [dict(r) for r in conn.execute(
        "SELECT * FROM run_collectors WHERE run_id = ?", (rid,))]
    return jsonify({
        "run": _row_to_dict(run),
        "correlated": bool(run["correlated"]),
        "collectors": collectors,
        "unique_ips": one("SELECT COUNT(*) FROM ip_addresses WHERE run_id = ?"),
        "unique_cidrs": one("SELECT COUNT(*) FROM cidr_blocks WHERE run_id = ?"),
        "certificates": one("SELECT COUNT(*) FROM certificates WHERE run_id = ?"),
        "certs_expiring_30d": one(
            "SELECT COUNT(*) FROM certificates WHERE run_id = ? "
            "AND days_remaining BETWEEN 0 AND 30"),
        "certs_broken": one(
            "SELECT COUNT(*) FROM certificates WHERE run_id = ? "
            "AND (expired OR self_signed OR mismatched OR untrusted)"),
        "hosts_in_claimable_ranges": one(
            "SELECT COUNT(*) FROM ip_addresses WHERE run_id = ? "
            "AND in_claimable_range"),
        "foreign_shared_ips": one(
            "SELECT COUNT(*) FROM ip_addresses WHERE run_id = ? "
            "AND foreign_domain_count > 0"),
        "discovered_new_names": one(
            "SELECT COUNT(*) FROM cert_names WHERE run_id = ? "
            "AND discovered_new AND NOT in_scope"),
    })


@api.get("/network/ips")
def network_ips():
    conn = get_db()
    run = resolve_run(conn, request.args.get("run"), request.args.get("project"))
    if not run:
        return jsonify({"rows": [], "total": 0}), 404
    page, page_size = _paginate(request)
    total = conn.execute(
        "SELECT COUNT(*) FROM ip_addresses WHERE run_id = ?", (run["id"],)
    ).fetchone()[0]
    rows = [dict(r) for r in conn.execute(
        "SELECT * FROM ip_addresses WHERE run_id = ? "
        "ORDER BY foreign_domain_count DESC, ip "
        "LIMIT ? OFFSET ?",
        (run["id"], page_size, (page - 1) * page_size),
    )]
    for r in rows:
        if r.get("ptr_json"):
            try:
                r["ptr"] = json.loads(r.pop("ptr_json"))
            except json.JSONDecodeError:
                r.pop("ptr_json", None)
    return jsonify({"rows": rows, "total": total, "page": page, "page_size": page_size,
                    "run": _row_to_dict(run)})


@api.get("/network/ips/<path:ip>")
def network_ip_detail(ip: str):
    conn = get_db()
    run = resolve_run(conn, request.args.get("run"), request.args.get("project"))
    if not run:
        return jsonify({"error": "no runs ingested yet"}), 404
    row = conn.execute(
        "SELECT * FROM ip_addresses WHERE run_id = ? AND ip = ?",
        (run["id"], ip),
    ).fetchone()
    if not row:
        return jsonify({"error": f"address not found in this run: {ip}"}), 404

    record = dict(row)
    if record.get("ptr_json"):
        try:
            record["ptr"] = json.loads(record.pop("ptr_json"))
        except json.JSONDecodeError:
            record.pop("ptr_json", None)

    hostnames = [
        dict(r) for r in conn.execute(
            "SELECT DISTINCT name, record_type, in_scope FROM dns_records "
            "WHERE run_id = ? AND value = ? ORDER BY name",
            (run["id"], ip))
    ]
    endpoints = [
        dict(r) for r in conn.execute(
            "SELECT endpoint_key, host, port, scheme, status_code, response_class "
            "FROM endpoints WHERE run_id = ? AND host_ip = ? ORDER BY host, port",
            (run["id"], ip))
    ]
    certs = [
        dict(r) for r in conn.execute(
            "SELECT DISTINCT c.* FROM certificates c "
            "JOIN cert_observations o ON o.cert_sha256 = c.cert_sha256 "
            "AND o.run_id = c.run_id WHERE c.run_id = ? AND o.ip = ?",
            (run["id"], ip))
    ]
    return jsonify({
        "ip": record, "hostnames": hostnames, "endpoints": endpoints,
        "certificates": certs, "run": _row_to_dict(run),
    })


@api.get("/network/cidrs")
def network_cidrs():
    conn = get_db()
    run = resolve_run(conn, request.args.get("run"), request.args.get("project"))
    if not run:
        return jsonify({"rows": [], "total": 0}), 404
    page, page_size = _paginate(request)
    total = conn.execute(
        "SELECT COUNT(*) FROM cidr_blocks WHERE run_id = ?", (run["id"],)
    ).fetchone()[0]
    rows = [dict(r) for r in conn.execute(
        "SELECT * FROM cidr_blocks WHERE run_id = ? "
        "ORDER BY observed_ip_count DESC, cidr LIMIT ? OFFSET ?",
        (run["id"], page_size, (page - 1) * page_size),
    )]
    return jsonify({"rows": rows, "total": total, "page": page, "page_size": page_size,
                    "run": _row_to_dict(run)})


@api.get("/network/cidrs/<path:cidr>")
def network_cidr_detail(cidr: str):
    conn = get_db()
    run = resolve_run(conn, request.args.get("run"), request.args.get("project"))
    if not run:
        return jsonify({"error": "no runs ingested yet"}), 404
    row = conn.execute(
        "SELECT * FROM cidr_blocks WHERE run_id = ? AND cidr = ?",
        (run["id"], cidr),
    ).fetchone()
    if not row:
        return jsonify({"error": f"range not found in this run: {cidr}"}), 404

    record = dict(row)
    ips = [
        dict(r) for r in conn.execute(
            "SELECT * FROM ip_addresses WHERE run_id = ? "
            "AND ip_sort_key BETWEEN ? AND ? ORDER BY ip_sort_key LIMIT 500",
            (run["id"], record["ip_start_key"], record["ip_end_key"]))
    ]
    return jsonify({"cidr": record, "ips": ips, "run": _row_to_dict(run)})


@api.get("/certs")
def certs_list():
    conn = get_db()
    run = resolve_run(conn, request.args.get("run"), request.args.get("project"))
    if not run:
        return jsonify({"rows": [], "total": 0}), 404
    page, page_size = _paginate(request)
    where = "run_id = ?"
    params: list[Any] = [run["id"]]
    status = request.args.get("status")
    if status == "expired":
        where += " AND expired"
    elif status == "self_signed":
        where += " AND self_signed"
    elif status == "mismatched":
        where += " AND mismatched"
    elif status == "broken":
        where += " AND (expired OR self_signed OR mismatched OR untrusted)"
    total = conn.execute(f"SELECT COUNT(*) FROM certificates WHERE {where}",
                        params).fetchone()[0]
    rows = [dict(r) for r in conn.execute(
        f"SELECT * FROM certificates WHERE {where} "
        f"ORDER BY days_remaining IS NULL, days_remaining ASC "
        f"LIMIT ? OFFSET ?",
        (*params, page_size, (page - 1) * page_size),
    )]
    for r in rows:
        r.pop("raw_json", None)
    return jsonify({"rows": rows, "total": total, "page": page, "page_size": page_size,
                    "run": _row_to_dict(run)})


@api.get("/certs/<sha256>")
def cert_detail(sha256: str):
    conn = get_db()
    run = resolve_run(conn, request.args.get("run"), request.args.get("project"))
    if not run:
        return jsonify({"error": "no runs ingested yet"}), 404
    row = conn.execute(
        "SELECT * FROM certificates WHERE run_id = ? AND cert_sha256 = ?",
        (run["id"], sha256),
    ).fetchone()
    if not row:
        return jsonify({"error": f"certificate not found in this run: {sha256}"}), 404

    record = dict(row)
    if record.get("raw_json"):
        try:
            record["raw"] = json.loads(record.pop("raw_json"))
        except json.JSONDecodeError:
            record.pop("raw_json", None)

    names = [
        dict(r) for r in conn.execute(
            "SELECT * FROM cert_names WHERE run_id = ? AND cert_sha256 = ? "
            "ORDER BY name", (run["id"], sha256))
    ]
    observations = [
        dict(r) for r in conn.execute(
            "SELECT * FROM cert_observations WHERE run_id = ? AND cert_sha256 = ? "
            "ORDER BY host, port", (run["id"], sha256))
    ]
    return jsonify({
        "certificate": record, "names": names, "observations": observations,
        "run": _row_to_dict(run),
    })


@api.get("/network/discovered")
def network_discovered():
    """Assets this scan found evidence of but never directly enumerated —
    domains named in a certificate's SAN list, and hostnames found via
    reverse DNS. Each row carries its provenance and can be handed straight
    to the next scan's target list."""
    conn = get_db()
    run = resolve_run(conn, request.args.get("run"), request.args.get("project"))
    if not run:
        return jsonify({"rows": []}), 404

    via_cert = [
        dict(r) for r in conn.execute(
            "SELECT DISTINCT name, cert_sha256 FROM cert_names "
            "WHERE run_id = ? AND discovered_new AND NOT in_scope AND NOT is_wildcard "
            "ORDER BY name", (run["id"],))
    ]
    for r in via_cert:
        r["via"] = "certificate"

    via_ptr = [
        dict(r) for r in conn.execute(
            "SELECT DISTINCT name, value AS ip FROM dns_records "
            "WHERE run_id = ? AND record_type = 'PTR' AND NOT in_scope "
            "ORDER BY name", (run["id"],))
    ]
    for r in via_ptr:
        r["via"] = "reverse_dns"

    return jsonify({"rows": via_cert + via_ptr, "run": _row_to_dict(run)})


# One-hop graph traversal: one shape for every node kind (ip/cidr/cert/host),
# so a single frontend component renders any of them instead of four bespoke
# views. Depth is deliberately capped at 1 with a hard result limit — an
# ungated Cloudflare IP or a wildcard cert can have thousands of edges.
_GRAPH_LIMIT = 200


@api.get("/graph/<kind>/<path:key>")
def graph_node(kind: str, key: str):
    conn = get_db()
    run = resolve_run(conn, request.args.get("run"), request.args.get("project"))
    if not run:
        return jsonify({"error": "no runs ingested yet"}), 404
    rid = run["id"]
    edges: list[dict] = []
    node: dict[str, Any] = {"kind": kind, "key": key, "label": key, "attrs": {}}

    if kind == "ip":
        row = conn.execute(
            "SELECT * FROM ip_addresses WHERE run_id = ? AND ip = ?",
            (rid, key)).fetchone()
        node["attrs"] = dict(row) if row else {}
        for r in conn.execute(
                "SELECT DISTINCT name, record_type FROM dns_records "
                "WHERE run_id = ? AND value = ? LIMIT ?", (rid, key, _GRAPH_LIMIT)):
            edges.append({"rel": "resolved_from", "kind": "host", "key": r["name"],
                         "label": r["name"], "note": r["record_type"]})
        if row and row["cidr"]:
            edges.append({"rel": "in_range", "kind": "cidr", "key": row["cidr"],
                         "label": row["cidr"]})
        for r in conn.execute(
                "SELECT DISTINCT c.cert_sha256, c.subject_cn FROM certificates c "
                "JOIN cert_observations o ON o.cert_sha256 = c.cert_sha256 "
                "AND o.run_id = c.run_id WHERE c.run_id = ? AND o.ip = ? LIMIT ?",
                (rid, key, _GRAPH_LIMIT)):
            edges.append({"rel": "presents_cert", "kind": "cert",
                         "key": r["cert_sha256"], "label": r["subject_cn"] or r["cert_sha256"]})

    elif kind == "cidr":
        row = conn.execute(
            "SELECT * FROM cidr_blocks WHERE run_id = ? AND cidr = ?",
            (rid, key)).fetchone()
        node["attrs"] = dict(row) if row else {}
        if row:
            for r in conn.execute(
                    "SELECT ip FROM ip_addresses WHERE run_id = ? "
                    "AND ip_sort_key BETWEEN ? AND ? LIMIT ?",
                    (rid, row["ip_start_key"], row["ip_end_key"], _GRAPH_LIMIT)):
                edges.append({"rel": "contains", "kind": "ip", "key": r["ip"],
                             "label": r["ip"]})

    elif kind == "cert":
        row = conn.execute(
            "SELECT * FROM certificates WHERE run_id = ? AND cert_sha256 = ?",
            (rid, key)).fetchone()
        node["attrs"] = dict(row) if row else {}
        node["label"] = (row["subject_cn"] if row else "") or key
        for r in conn.execute(
                "SELECT name FROM cert_names WHERE run_id = ? AND cert_sha256 = ? "
                "LIMIT ?", (rid, key, _GRAPH_LIMIT)):
            edges.append({"rel": "covers_name", "kind": "host", "key": r["name"],
                         "label": r["name"]})
        for r in conn.execute(
                "SELECT DISTINCT ip FROM cert_observations WHERE run_id = ? "
                "AND cert_sha256 = ? LIMIT ?", (rid, key, _GRAPH_LIMIT)):
            if r["ip"]:
                edges.append({"rel": "presented_by", "kind": "ip", "key": r["ip"],
                             "label": r["ip"]})

    elif kind == "host":
        for r in conn.execute(
                "SELECT record_type, value FROM dns_records "
                "WHERE run_id = ? AND name = ? LIMIT ?", (rid, key, _GRAPH_LIMIT)):
            if r["record_type"] in ("A", "AAAA"):
                edges.append({"rel": "resolves_to", "kind": "ip", "key": r["value"],
                             "label": r["value"], "note": r["record_type"]})
        for r in conn.execute(
                "SELECT DISTINCT c.cert_sha256, c.subject_cn FROM cert_names n "
                "JOIN certificates c ON c.cert_sha256 = n.cert_sha256 "
                "AND c.run_id = n.run_id WHERE n.run_id = ? AND n.name = ? LIMIT ?",
                (rid, key, _GRAPH_LIMIT)):
            edges.append({"rel": "presents_cert", "kind": "cert",
                         "key": r["cert_sha256"], "label": r["subject_cn"] or r["cert_sha256"]})
    else:
        return jsonify({"error": f"unknown graph node kind: {kind!r}"}), 400

    truncated = len(edges) >= _GRAPH_LIMIT
    return jsonify({"node": node, "edges": edges[:_GRAPH_LIMIT],
                    "truncated": truncated, "run": _row_to_dict(run)})


# ── Phase 5: inventories, saved views, exports ──────────────────────────────

_INVENTORY_KINDS = ("technology", "infrastructure", "auth", "takeover")


@api.get("/inventory/<kind>")
def inventory(kind: str):
    from ..analytics import inventory as inv

    if kind not in _INVENTORY_KINDS:
        return jsonify({"error": f"unknown inventory {kind!r}",
                        "available": list(_INVENTORY_KINDS)}), 404

    conn = get_db()
    cfg = get_config()
    run = resolve_run(conn, request.args.get("run"), request.args.get("project"))
    if not run:
        return jsonify({"error": "no runs ingested yet"}), 404

    ruleset = _ruleset()
    if kind == "technology":
        payload = inv.technology(conn, run["id"], ruleset.lifecycle)
    elif kind == "infrastructure":
        payload = inv.infrastructure(conn, run["id"])
    elif kind == "auth":
        payload = inv.auth_surfaces(conn, run["id"])
    else:
        payload = inv.takeover(conn, run["id"], ruleset.takeover)

    payload["run"] = _row_to_dict(run)
    payload["kind"] = kind
    if kind == "infrastructure":
        payload["ownership_configured"] = cfg.has_ownership
        payload["ownership_note"] = cfg.ownership_note
    return jsonify(payload)


@api.get("/ownership")
def ownership():
    """Ownership state, so the UI can say plainly when no register exists."""
    cfg = get_config()
    conn = get_db()
    run = resolve_run(conn, request.args.get("run"), request.args.get("project"))

    by_unit = []
    if run and cfg.has_ownership:
        by_unit = [
            dict(r) for r in conn.execute(
                """SELECT COALESCE(NULLIF(business_unit,''),'Unassigned') AS unit,
                          COALESCE(NULLIF(owner,''),'Unassigned') AS owner,
                          COALESCE(NULLIF(criticality,''),'unset') AS criticality,
                          COUNT(*) AS hosts,
                          SUM(CASE WHEN risk_band IN ('critical','high')
                                   THEN 1 ELSE 0 END) AS needs_attention
                     FROM host_rollup WHERE run_id = ?
                    GROUP BY unit, owner, criticality
                    ORDER BY needs_attention DESC, hosts DESC""",
                (run["id"],))
        ]

    return jsonify({
        "configured": cfg.has_ownership,
        "note": cfg.ownership_note,
        "tiers": cfg.ownership.get("tiers") or {},
        "by_unit": by_unit,
    })


# ── Saved views ─────────────────────────────────────────────────────────────

@api.get("/views")
def list_views():
    conn = get_db()
    project = request.args.get("project")
    sql = ("SELECT v.*, p.slug AS project_slug FROM saved_views v "
           "LEFT JOIN projects p ON p.id = v.project_id")
    params: list = []
    if project:
        sql += " WHERE p.slug = ? OR v.project_id IS NULL"
        params.append(project)
    sql += " ORDER BY v.use_count DESC, v.name"

    rows = []
    for row in conn.execute(sql, params):
        record = dict(row)
        try:
            record["state"] = json.loads(record.pop("state_json") or "{}")
        except json.JSONDecodeError:
            record["state"] = {}
        rows.append(record)

    catalog = get_catalog()
    return jsonify({"views": rows, "builtin": catalog.filter_presets})


@api.post("/views")
def save_view():
    from ..ingest.store import now_iso

    body = request.get_json(silent=True) or {}
    name = (body.get("name") or "").strip()
    if not name:
        return jsonify({"error": "a name is required"}), 400
    if len(name) > 80:
        return jsonify({"error": "name is too long (80 characters maximum)"}), 400

    conn = get_db()
    project_id = None
    if body.get("project"):
        row = conn.execute("SELECT id FROM projects WHERE slug = ?",
                           (body["project"],)).fetchone()
        project_id = row["id"] if row else None

    state = body.get("state") or {}
    # The state is replayed into the query layer, so column names must be
    # validated now rather than trusted at read time.
    catalog = get_catalog()
    for column in (state.get("filters") or {}):
        if column not in catalog:
            return jsonify({"error": f"unknown column in filters: {column}"}), 400
    for column in (state.get("columns") or []):
        if column not in catalog:
            return jsonify({"error": f"unknown column: {column}"}), 400

    conn.execute(
        """INSERT INTO saved_views
             (project_id, name, description, view, state_json, created_at, updated_at)
           VALUES (?,?,?,?,?,?,?)
           ON CONFLICT(project_id, view, name) DO UPDATE SET
             state_json = excluded.state_json,
             description = excluded.description,
             updated_at = excluded.updated_at""",
        (project_id, name, body.get("description"),
         body.get("view", "endpoints"), json.dumps(state), now_iso(), now_iso()),
    )
    conn.commit()
    return jsonify({"ok": True, "name": name}), 201


@api.delete("/views/<int:view_id>")
def delete_view(view_id: int):
    conn = get_db()
    row = conn.execute("SELECT id FROM saved_views WHERE id = ?",
                       (view_id,)).fetchone()
    if row is None:
        return jsonify({"error": "view not found"}), 404
    conn.execute("DELETE FROM saved_views WHERE id = ?", (view_id,))
    conn.commit()
    return jsonify({"ok": True})


@api.post("/views/<int:view_id>/used")
def touch_view(view_id: int):
    conn = get_db()
    conn.execute("UPDATE saved_views SET use_count = use_count + 1 WHERE id = ?",
                 (view_id,))
    conn.commit()
    return jsonify({"ok": True})


# ── Workbook export ─────────────────────────────────────────────────────────

@api.route("/export/workbook", methods=["GET", "POST"])
def export_workbook():
    """Multi-sheet XLSX of the current run.

    Honours the active filter for the endpoints sheet, so an export matches what
    the operator is looking at rather than dumping everything.
    """
    import io

    from ..analytics import inventory as inv
    from ..export.redact import Redactor
    from ..export.xlsx import write_workbook

    conn, catalog = get_db(), get_catalog()
    args = _query_args()
    run = resolve_run(conn, args["run"], args["project"])
    if not run:
        return jsonify({"error": "no runs ingested yet"}), 404

    redactor = Redactor() if request.args.get("redact") in ("1", "true") else None
    ruleset = _ruleset()

    columns = [c for c in (args["columns"] or catalog.default_visible())
               if c in catalog]
    grid = facets.query_endpoints(
        conn, run["id"], catalog, filters=args["filters"], search=args["search"],
        sort=args["sort"], page=1, page_size=100000, columns=columns,
    )
    endpoint_rows = [
        {c: (", ".join(str(x) for x in r[c]) if isinstance(r.get(c), list)
             else r.get(c)) for c in columns}
        for r in grid["rows"]
    ]

    findings_rows = []
    for row in conn.execute(
        "SELECT severity, confidence, rule_id, asset_key, title, status, "
        "detail_json FROM findings WHERE project_id = ? ORDER BY severity",
        (run["project_id"],)
    ):
        record = dict(row)
        try:
            detail = json.loads(record.pop("detail_json") or "{}")
        except json.JSONDecodeError:
            detail = {}
        record["endpoints"] = detail.get("endpoint_count", 0)
        record["score"] = detail.get("max_score", 0)
        record["why"] = detail.get("why", "")
        record["remediation"] = detail.get("remediation", "")
        findings_rows.append(record)

    tech = inv.technology(conn, run["id"], ruleset.lifecycle)
    infra = inv.infrastructure(conn, run["id"], ip_limit=500)
    auth = inv.auth_surfaces(conn, run["id"])
    over = inv.takeover(conn, run["id"], ruleset.takeover)

    sheets: list[tuple[str, list[str], list[dict]]] = [
        ("Endpoints", columns, endpoint_rows),
        ("Findings", ["severity", "confidence", "rule_id", "asset_key", "title",
                      "endpoints", "score", "status", "why", "remediation"],
         findings_rows),
        ("Technology", ["name", "hosts", "version_count", "versions"],
         [{**t, "versions": ", ".join(t["versions"])} for t in tech["tech"]]),
        ("End of life", ["name", "eol_date", "years_past_eol", "severity", "hosts"],
         tech["eol"]),
        ("Addresses", ["ip", "family", "hosts", "providers", "cdn"],
         [{**a, "providers": ", ".join(a["providers"]),
           "cdn": ", ".join(a["cdn"])} for a in infra["addresses"]]),
        ("Ports", ["port", "total", "real", "serving", "aliases", "artefacts"],
         infra["port_rows"]),
        ("Auth surfaces", ["endpoint_key", "type", "federated", "over_http",
                           "no_waf", "risk_band", "env", "title"],
         [e for g in auth["groups"] for e in g["endpoints"]]),
        ("Takeover candidates", ["host", "grade", "provider", "confidence",
                                 "cname_final", "status_code", "origin_health"],
         over["candidates"]),
    ]

    if redactor:
        sheets = [
            (name, cols, [redactor.row(r) for r in rows])
            for name, cols, rows in sheets
        ]
        sheets.append(("Redaction notice", ["note"], [{"note": redactor.note()}]))

    buffer = io.BytesIO()
    write_workbook(buffer, sheets, title=f"frogscope — {run['run_key']}")
    buffer.seek(0)

    suffix = "-redacted" if redactor else ""
    return Response(
        buffer.getvalue(),
        mimetype="application/vnd.openxmlformats-officedocument."
                 "spreadsheetml.sheet",
        headers={"Content-Disposition":
                 f'attachment; filename="{run["run_key"]}{suffix}.xlsx"'},
    )
