"""Command-line interface.

Exit codes are meaningful so this can be driven from cron or CI:
  0 ok · 1 error · 2 usage · 3 duplicate ingest · 4 store integrity
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

from .config import ConfigError, dump_config, load_config
from .db.connection import check_features, connect
from .db.migrate import current_version, migrate
from .ingest import store
from .scan import options as scan_options

EXIT_OK, EXIT_ERROR, EXIT_USAGE, EXIT_DUPLICATE, EXIT_STORE = 0, 1, 2, 3, 4
# Distinct code so a cron job can tell 'posture worsened' from 'the tool broke'.
EXIT_THRESHOLD = 5


def _fmt_table(rows: list[dict], columns: list[str]) -> str:
    if not rows:
        return "(no rows)"
    widths = {c: len(c) for c in columns}
    cells = []
    for row in rows:
        rendered = {}
        for c in columns:
            value = row.get(c)
            if isinstance(value, list):
                value = ",".join(str(v) for v in value)
            elif value is None:
                value = ""
            elif isinstance(value, bool):
                value = "yes" if value else ""
            text = str(value)
            if len(text) > 60:
                text = text[:57] + "..."
            rendered[c] = text
            widths[c] = max(widths[c], len(text))
        cells.append(rendered)

    header = "  ".join(c.ljust(widths[c]) for c in columns)
    rule = "  ".join("-" * widths[c] for c in columns)
    body = "\n".join(
        "  ".join(r[c].ljust(widths[c]) for c in columns) for r in cells
    )
    return f"{header}\n{rule}\n{body}"


# ── Commands ────────────────────────────────────────────────────────────────

def cmd_init(args) -> int:
    cfg = load_config(args.config, args.data)
    cfg.data_dir.mkdir(parents=True, exist_ok=True)
    cfg.raw_dir.mkdir(parents=True, exist_ok=True)
    conn = connect(cfg.db_path)
    try:
        applied = migrate(conn, verbose=True)
    finally:
        conn.close()
    print(f"data dir : {cfg.data_dir}")
    print(f"database : {cfg.db_path}")
    print(f"migrations applied: {applied or 'none (already current)'}")
    return EXIT_OK


def cmd_doctor(args) -> int:
    problems: list[str] = []
    try:
        cfg = load_config(args.config, args.data)
        print(f"config       OK  ({cfg.config_hash}, {len(cfg.columns['columns'])} columns)")
    except ConfigError as exc:
        print(f"config       FAIL\n{exc}")
        return EXIT_ERROR

    try:
        import flask
        print(f"flask        OK  {flask.__version__}")
    except ImportError:
        problems.append("Flask is not installed (pip install -r requirements.txt)")

    conn = connect(cfg.db_path)
    try:
        features = check_features(conn)
        for name, ok in features.items():
            print(f"sqlite {name:<7}{'OK' if ok else 'MISSING'}")
            if not ok:
                problems.append(f"SQLite lacks {name}, which the query layer needs")
        print(f"schema       v{current_version(conn)}")
        runs = conn.execute("SELECT COUNT(*) AS n FROM runs").fetchone()["n"] \
            if current_version(conn) else 0
        print(f"runs         {runs}")
    finally:
        conn.close()

    env_cfg = cfg.classify.get("env") or {}
    custom = env_cfg.get("custom_keywords") or {}
    if custom:
        count = sum(len(v or []) for v in custom.values())
        print(f"naming      {count} site-specific environment token(s) configured")
    else:
        # Not a problem, but worth surfacing: every estate has internal shorthand,
        # and until it is declared those hosts land in `unclassified`.
        print("naming      no site-specific environment tokens "
              "(config/classify.yaml: env.custom_keywords)")

    # Reported here because the failure mode is believing alerting works when it
    # does not — an unset ${VAR} leaves a target with an empty URL.
    from .notify import alerts as _alerts
    try:
        notify_cfg = _alerts.load_notify_config(cfg.config_dir)
    except Exception as exc:  # noqa: BLE001
        problems.append(f"notify.yaml is unreadable: {exc}")
    else:
        if not notify_cfg.get("enabled"):
            print("notify       off (notify.yaml has enabled: false)")
        else:
            usable, skipped = _alerts.active_targets(notify_cfg)
            names = ", ".join(t.get("name", "?") for t in usable) or "none"
            print(f"notify       on  -> {names}")
            for reason in skipped:
                if "disabled" not in reason:
                    problems.append(f"notification target {reason}")

    if problems:
        print("\nproblems:")
        for p in problems:
            print(f"  - {p}")
        return EXIT_ERROR
    print("\nall good")
    return EXIT_OK


def cmd_config(args) -> int:
    cfg = load_config(args.config, args.data)
    print(dump_config(cfg))
    return EXIT_OK


def cmd_validate(args) -> int:
    from .ingest import pipeline, quality

    cfg = load_config(args.config, args.data)
    records, rollups, load_result, collapse, _entities = pipeline.analyse(args.file, cfg)

    print(f"file            {args.file}")
    print(f"format          {load_result.fmt}")
    print(f"source columns  {len(load_result.source_columns)}")
    print(f"raw rows        {load_result.row_count}")
    print(f"endpoints       {len(records)}   (after collapsing duplicate host:port)")
    print(f"hosts           {len(rollups)}")
    print()

    c = collapse.as_dict()
    print("intra-run duplicates")
    print(f"  groups          {c['duplicate_groups']}")
    print(f"  excess rows     {c['duplicate_rows']}")
    print(f"  inconsistent    {c['inconsistent_groups']}")
    print(f"  scheme conflict {c['scheme_conflicts']}")
    print(f"  group sizes     {c['group_size_hist']}")
    print()

    summary = pipeline._summarise(records, rollups)
    for key in ("real_endpoints", "scan_artifacts", "cf_alias_ports", "serving",
                "waf_protected", "no_waf", "no_waf_hosts",
                "origin_exposed", "origin_exposed_hosts", "cdn_bypass_hosts",
                "auth_surfaces",
                "mgmt_surfaces", "remote_access", "azure_app_proxy",
                "cleartext_no_upgrade", "nonprod_exposed", "broken_origin",
                "unique_ips"):
        print(f"{key:<24}{summary[key]}")
    print(f"{'ports':<24}{summary['ports']}")
    print()
    print("by response class")
    for name, count in summary["by_response_class"].items():
        print(f"  {count:>6}  {name}")

    census = quality.column_census(
        [r.get("raw") or {} for r in load_result.records], load_result.source_columns
    )
    empty = [c["column_name"] for c in census if c["fill_pct"] == 0.0]
    print()
    print(f"empty source columns ({len(empty)}): {', '.join(empty) or 'none'}")

    warnings = list(load_result.warnings) + quality.completeness_check(
        records, source_mtime=Path(args.file).stat().st_mtime
    )
    if warnings:
        print()
        print("warnings")
        for w in warnings[:20]:
            print(f"  ! {w}")
        if len(warnings) > 20:
            print(f"  ... and {len(warnings) - 20} more")

    suggestions = quality.suggest_httpx_flags(census)
    if suggestions:
        print()
        print("richer data available from httpx")
        for s in suggestions:
            print(f"  {s['flag']:<18}{s['unlocks']}")
        print()
        print(f"  {quality.recommended_command(census)}")

    return EXIT_OK


def cmd_ingest(args) -> int:
    from .ingest import pipeline

    cfg = load_config(args.config, args.data)
    conn = connect(cfg.db_path)
    try:
        migrate(conn)
        for path in args.files:
            try:
                result = pipeline.ingest(
                    conn, cfg, path,
                    project=args.project, project_name=args.project_name,
                    label=args.label, run_kind=args.kind,
                    force=args.force,
                    allow_incomplete=args.allow_incomplete,
                    allow_drift=args.allow_drift,
                    keep_raw=not args.no_archive,
                    correlation=args.correlation,
                )
            except pipeline.DuplicateRun as exc:
                print(f"{path}: {exc}", file=sys.stderr)
                return EXIT_DUPLICATE
            except pipeline.IncompleteScan as exc:
                print(f"{path}: {exc}", file=sys.stderr)
                for w in exc.warnings:
                    print(f"  ! {w}", file=sys.stderr)
                flag = "--" + exc.override.replace("_", "-")
                print(f"  pass {flag} to ingest it anyway", file=sys.stderr)
                return EXIT_ERROR

            if args.json:
                print(json.dumps({
                    "run_id": result.run_id, "run_key": result.run_key,
                    "rows": result.row_count, "endpoints": result.endpoint_count,
                    "hosts": result.host_count, "warnings": result.warnings,
                    "summary": result.summary,
                }, indent=2))
            else:
                print(f"ingested {path}")
                print(f"  run        {result.run_key} (id {result.run_id})")
                print(f"  rows       {result.row_count} -> "
                      f"{result.endpoint_count} endpoints, {result.host_count} hosts")
                collapse = result.collapse
                if collapse["duplicate_groups"]:
                    print(f"  collapsed  {collapse['duplicate_rows']} duplicate rows "
                          f"across {collapse['duplicate_groups']} host:port groups")
                s = result.summary
                print(f"  real       {s['real_endpoints']} endpoints "
                      f"({s['scan_artifacts']} scan artefacts, "
                      f"{s['cf_alias_ports']} Cloudflare aliases excluded)")
                print(f"  serving    {s['serving']}")
                print(f"  no WAF     {s['no_waf']} endpoints "
                      f"({s['no_waf_hosts']} hosts)")
                print(f"  direct     {s['origin_exposed_hosts']} hosts reached "
                      f"with no proxy at all")
                for w in result.warnings[:10]:
                    print(f"  ! {w}")
    finally:
        conn.close()
    return EXIT_OK


def cmd_scan(args) -> int:
    """Run a live scan from the terminal — the same path `POST /api/scan`
    uses (subfinder/domain resolution -> httpx -> ingest), so a scan run here
    and one run from the browser produce identical, indistinguishable runs.

    Exists so IP/CIDR target support and DNS/network/TLS correlation — all
    of it unconditional now — can be exercised end-to-end without a browser
    in front of them.
    """
    import time as _time

    from .ingest import pipeline
    from .scan import OptionError, ScanRun
    from .scan.runner import Cancelled, NeedsApproval, ScanError

    payload = {
        "targets": args.targets,
        "profile": args.profile,
        "subfinder": not args.no_subfinder,
        "authorised": args.authorised,
        "approved_hosts": args.approve_hosts,
    }
    if args.rate_limit is not None:
        payload["rate_limit"] = args.rate_limit
    if args.threads is not None:
        payload["threads"] = args.threads
    if args.timeout is not None:
        payload["timeout"] = args.timeout
    if args.retries is not None:
        payload["retries"] = args.retries

    try:
        options = scan_options.parse(payload)
    except OptionError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    def on_progress(progress) -> None:
        if not args.json:
            print(f"  [{progress.phase}] {progress.message}", file=sys.stderr)

    run = ScanRun(options, on_progress=on_progress)
    started_at = _time.strftime("%Y-%m-%dT%H:%M:%SZ", _time.gmtime())
    try:
        csv_path = run.run()
    except NeedsApproval as exc:
        print(f"{len(exc.hosts)} hosts found — re-run with "
              f"--approve-hosts {len(exc.hosts)} to confirm and probe them",
              file=sys.stderr)
        return EXIT_USAGE
    except (ScanError, Cancelled) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    cfg = load_config(args.config, args.data)
    conn = connect(cfg.db_path)
    try:
        migrate(conn)
        result = pipeline.ingest(
            conn, cfg, csv_path, project=args.project,
            project_name=args.project_name, label=args.label,
            supervised=True, trust_mtime=False, scanned_at=started_at,
            allow_drift=True, correlation=run.artifacts.get("correlation"),
        )
        conn.execute(
            # `correlated` is set by ingest() itself, from whether it was
            # actually given a correlation sidecar to attach — not repeated
            # here.
            "UPDATE runs SET source_kind = 'scan', scan_json = ?, "
            "target_kind = ? WHERE id = ?",
            (json.dumps(options.as_dict()), options.target_kind, result.run_id))
        conn.commit()
    finally:
        conn.close()

    if args.json:
        print(json.dumps({
            "run_id": result.run_id, "run_key": result.run_key,
            "target_kind": options.target_kind,
            "hosts_probed": len(_read_lines(csv_path.parent / "hosts.txt")),
            "endpoints": result.endpoint_count, "hosts": result.host_count,
        }, indent=2))
    else:
        print(f"scanned {options.target_kind} target(s)")
        print(f"  run       {result.run_key} (id {result.run_id})")
        print(f"  endpoints {result.endpoint_count}, hosts {result.host_count}")
    return EXIT_OK


def _read_lines(path: Path) -> list[str]:
    try:
        return [line for line in path.read_text(encoding="utf-8").splitlines() if line]
    except OSError:
        return []


def cmd_runs(args) -> int:
    cfg = load_config(args.config, args.data)
    conn = connect(cfg.db_path)
    try:
        rows = [
            dict(r) for r in conn.execute(
                "SELECT r.id, r.run_key, r.label, r.run_kind, r.started_at, "
                "r.endpoint_count, r.host_count, r.row_count, r.incomplete, "
                "p.slug AS project FROM runs r JOIN projects p ON p.id = r.project_id "
                "ORDER BY COALESCE(r.started_at,''), r.id"
            )
        ]
    finally:
        conn.close()
    if args.json:
        print(json.dumps(rows, indent=2))
    else:
        print(_fmt_table(rows, ["id", "project", "run_key", "label", "run_kind",
                                "started_at", "endpoint_count", "host_count",
                                "incomplete"]))
    return EXIT_OK


def cmd_query(args) -> int:
    from .api._db import resolve_run as _resolve
    from .query import facets
    from .query.catalog import Catalog
    from .query.filters import FilterError

    cfg = load_config(args.config, args.data)
    conn = connect(cfg.db_path)
    catalog = Catalog(cfg)
    try:
        run = _resolve(conn, args.run, args.project)
        if not run:
            print("no runs ingested yet", file=sys.stderr)
            return EXIT_STORE

        filters: dict = {}
        for clause in args.filter or []:
            for part in clause.split(","):
                part = part.strip()
                if not part:
                    continue
                if "!=" in part:
                    key, _, value = part.partition("!=")
                    filters.setdefault(key.strip(), []).append(f"!{value.strip()}")
                elif ">=" in part:
                    key, _, value = part.partition(">=")
                    filters[key.strip()] = {"min": value.strip()}
                elif "<=" in part:
                    key, _, value = part.partition("<=")
                    filters[key.strip()] = {"max": value.strip()}
                elif "=" in part:
                    key, _, value = part.partition("=")
                    filters.setdefault(key.strip(), []).append(value.strip())
                else:
                    filters.setdefault(part, []).append("true")

        columns = ([c.strip() for c in args.columns.split(",")]
                   if args.columns else catalog.default_visible())

        try:
            result = facets.query_endpoints(
                conn, run["id"], catalog, filters=filters, search=args.search or "",
                sort=args.sort, page=1, page_size=args.limit, columns=columns,
            )
        except FilterError as exc:
            print(f"bad filter: {exc}", file=sys.stderr)
            return EXIT_USAGE
    finally:
        conn.close()

    rows = result["rows"]
    if args.format == "json":
        print(json.dumps(rows, indent=2, default=str))
    elif args.format == "csv":
        import csv as _csv
        writer = _csv.DictWriter(sys.stdout, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({
                c: ("|".join(map(str, row[c])) if isinstance(row.get(c), list)
                    else row.get(c, ""))
                for c in columns
            })
    else:
        print(_fmt_table(rows, columns))
        print()
        print(f"showing {len(rows)} of {result['total']} matching endpoints "
              f"in run {run['run_key']}")
    return EXIT_OK


def cmd_serve(args) -> int:
    from .scan.scheduler import Scheduler
    from .server import create_app

    cfg = load_config(args.config, args.data)
    app = create_app(cfg)
    url = f"http://{args.host}:{args.port}/"
    print(f"frogscope serving on {url}")
    if args.host in ("127.0.0.1", "localhost"):
        print("bound to localhost only")
    if args.open:
        import threading
        import webbrowser
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()

    # v2: scheduled scanning. Guarded against Werkzeug's --reload, which
    # forks a monitor process that re-runs this function in the launcher
    # process too — without this check, a reloaded dev server would start
    # two scheduler threads ticking the same database. WERKZEUG_RUN_MAIN is
    # only set in the actual worker process the reloader supervises, never
    # in the initial launcher.
    if not args.reload or os.environ.get("WERKZEUG_RUN_MAIN") == "true":
        Scheduler(cfg).start()

    app.run(host=args.host, port=args.port, debug=args.reload, use_reloader=args.reload)
    return EXIT_OK



# ── Detection catalogue ─────────────────────────────────────────────────────

def _catalogue_meta(cfg):
    import yaml
    path = cfg.config_dir / "catalogue.yaml"
    if not path.exists():
        return {}
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}



# ── Store maintenance ───────────────────────────────────────────────────────

def cmd_store_compact(args) -> int:
    """Prune archived source files, keeping the newest N per project.

    Only the ARCHIVES go. Every metric, finding, and diff already lives in the
    database, so pruning costs the ability to re-derive an old run from source —
    not the run itself. The UI says "source file pruned" rather than pretending
    the run is incomplete.
    """
    cfg = load_config(args.config, args.data)
    conn = connect(cfg.db_path)
    try:
        sql = ("SELECT r.id, r.run_key, r.started_at, p.slug "
               "FROM runs r JOIN projects p ON p.id = r.project_id ")
        params: list = []
        if args.project:
            sql += "WHERE p.slug = ? "
            params.append(args.project)
        sql += "ORDER BY p.slug, COALESCE(r.started_at, '') DESC, r.id DESC"
        rows = conn.execute(sql, params).fetchall()
    finally:
        conn.close()

    seen: dict[str, int] = {}
    freed = 0
    pruned = 0
    kept = 0
    for row in rows:
        slug = row["slug"]
        seen[slug] = seen.get(slug, 0) + 1
        archive = cfg.raw_dir / f"{row['run_key']}.csv.gz"
        if seen[slug] <= args.keep_last:
            kept += 1
            continue
        if not archive.exists():
            continue
        size = archive.stat().st_size
        if args.dry_run:
            print(f"  would remove {archive.name} ({size // 1024} KB)")
        else:
            archive.unlink()
            print(f"  removed {archive.name} ({size // 1024} KB)")
        freed += size
        pruned += 1

    print()
    print(f"kept the newest {args.keep_last} archive(s) per project "
          f"({kept} run(s))")
    print(f"{'would free' if args.dry_run else 'freed'} {freed // 1024} KB "
          f"across {pruned} file(s)")
    if pruned and not args.dry_run:
        print("Metrics, findings, and diffs are unaffected — only the ability to "
              "re-derive those runs from source is gone.")
    return EXIT_OK


def cmd_store_verify(args) -> int:
    """Look for the inconsistencies that actually happen.

    Chiefly a search index out of step with the rows it indexes: `endpoints_fts`
    has no foreign key, so anything that deletes endpoints without clearing it
    leaves the global search returning hosts that no longer exist.
    """
    cfg = load_config(args.config, args.data)
    conn = connect(cfg.db_path)
    problems: list[str] = []
    try:
        endpoints = conn.execute("SELECT COUNT(*) AS n FROM endpoints").fetchone()["n"]
        fts = conn.execute("SELECT COUNT(*) AS n FROM endpoints_fts").fetchone()["n"]
        print(f"endpoints           {endpoints}")
        print(f"search index rows   {fts}")
        if endpoints != fts:
            problems.append(
                f"search index holds {fts} rows for {endpoints} endpoints — "
                f"global search may return hosts that no longer exist. "
                f"`frogscope reindex` rebuilds it.")

        for table in ("findings", "assets", "changes", "asset_presence",
                      "saved_views", "notifications"):
            orphans = conn.execute(
                f"SELECT COUNT(*) AS n FROM {table} "
                f"WHERE project_id NOT IN (SELECT id FROM projects)").fetchone()["n"]
            if orphans:
                problems.append(f"{table}: {orphans} row(s) with no project")

        runs = conn.execute(
            "SELECT r.run_key FROM runs r ORDER BY r.run_key").fetchall()
        missing = [r["run_key"] for r in runs
                   if not (cfg.raw_dir / f"{r['run_key']}.csv.gz").exists()]
        print(f"runs                {len(runs)}")
        print(f"archived sources    {len(runs) - len(missing)}")
        if missing:
            # Expected after `store compact`, so stated as information.
            print(f"  {len(missing)} run(s) have no archived source "
                  f"(normal after `store compact`)")

        integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
        print(f"sqlite integrity    {integrity}")
        if integrity != "ok":
            problems.append(f"SQLite integrity check returned {integrity!r}")
    finally:
        conn.close()

    print()
    if problems:
        for problem in problems:
            print(f"  - {problem}")
        return EXIT_STORE
    print("store is consistent")
    return EXIT_OK


def cmd_catalogue_status(args) -> int:
    """What was reviewed, when, and whether another review is due."""
    from datetime import date

    from .ingest import fingerprint

    cfg = load_config(args.config, args.data)
    meta = _catalogue_meta(cfg)
    from .scoring.rules import load_ruleset

    catalogue = fingerprint.load_catalogue(cfg.config_dir)
    ruleset = load_ruleset(cfg.config_dir)

    print(f"catalogue version   {meta.get('catalogue_version', '?')}")
    print(f"fingerprints        {catalogue.total} "
          f"({len(catalogue.panels)} panels, {len(catalogue.default_pages)} default "
          f"pages, {len(catalogue.disclosure)} disclosure, "
          f"{len(catalogue.storage)} storage)")
    print(f"scoring rules       {len(ruleset.rules)}")

    import yaml
    takeover = yaml.safe_load(
        (cfg.config_dir / "takeover.yaml").read_text(encoding="utf-8")) or {}
    providers = takeover.get("providers") or []
    claimable = sum(1 for p in providers if p.get("claimable"))
    print(f"takeover providers  {len(providers)} ({claimable} claimable)")
    print()

    interval = int(meta.get("review_interval_days") or 180)
    today = date.today()
    for source in meta.get("sources") or []:
        reviewed = source.get("last_reviewed")
        line = f"  {source.get('name', source.get('id'))}"
        if reviewed:
            try:
                when = reviewed if isinstance(reviewed, date) else \
                    date.fromisoformat(str(reviewed))
                age = (today - when).days
                due = "DUE" if age >= interval else f"due in {interval - age}d"
                line += f"\n    last reviewed {when.isoformat()} ({age}d ago, {due})"
            except ValueError:
                line += f"\n    last reviewed {reviewed}"
        print(line)
        adopted = source.get("adopted") or []
        excluded = source.get("excluded") or []
        print(f"    adopted {len(adopted)} area(s), deliberately excluded "
              f"{len(excluded)}")
        print(f"    {source.get('url', '')}")
    print()

    blocked = meta.get("blocked_by_input") or []
    if blocked:
        # Stated up front: "no findings" and "could not look" are different
        # answers, and only one of them is reassuring.
        print("checks that cannot fire on the data currently collected:")
        for entry in blocked:
            fields = ", ".join(entry.get("fields") or [])
            print(f"  {fields:44} {entry.get('unlocks_with', '')}")
    print()
    print("to refresh: follow the procedure in README.md "
          "(Maintenance -> refresh the detections)")
    return EXIT_OK


def cmd_catalogue_coverage(args) -> int:
    """How much of the catalogue this run's data could actually reach."""
    from .ingest import fingerprint

    cfg = load_config(args.config, args.data)
    conn = connect(cfg.db_path)
    try:
        from .api._db import resolve_run as _resolve
        run = _resolve(conn, args.run, args.project)
        if not run:
            print("no runs ingested yet", file=sys.stderr)
            return EXIT_STORE

        # Which optional fields this run actually carries. Presence of a VALUE,
        # not of a column: `raw_json` contains the string "body_preview" as a key
        # even when every row's value is empty, which made an earlier version
        # report full coverage on a scan that collected no bodies at all.
        present = {"title", "webserver", "tech_names", "cpe_products", "port"}
        for field, expression in (
            ("tls_version", "COALESCE(tls_version, '') != ''"),
            ("favicon_md5", "COALESCE(favicon_md5, '') != ''"),
            ("cert_not_after", "COALESCE(cert_not_after, '') != ''"),
            ("body_preview",
             "json_extract(raw_json, '$.body_preview') IS NOT NULL "
             "AND json_extract(raw_json, '$.body_preview') != ''"),
        ):
            row = conn.execute(
                f"SELECT COUNT(*) AS n FROM endpoints WHERE run_id = ? "
                f"AND {expression}", (run["id"],)).fetchone()
            if row["n"]:
                present.add(field)

        catalogue = fingerprint.load_catalogue(cfg.config_dir)
        report = fingerprint.coverage(catalogue, present)

        print(f"run                 {run['run_key']}")
        print(f"catalogue version   {report['catalogue_version']}")
        print(f"fingerprints        {report['total']}")
        print(f"  fully evaluable   {report['evaluable']}")
        print(f"  partly evaluable  {report['partial']}  "
              f"(can fire, but with less evidence than designed)")
        print(f"  cannot fire       {report['blocked']}")
        if report["blocked_by_field"]:
            print()
            print("blocked because the scan did not collect:")
            for field, count in report["blocked_by_field"].items():
                print(f"  {field:24} {count} fingerprint(s)")
            print()
            print("run `frogscope suggest-httpx` for the flags that unlock these.")

        matched = conn.execute(
            "SELECT COUNT(*) AS n FROM endpoints WHERE run_id = ? "
            "AND fingerprint_count > 0", (run["id"],)).fetchone()["n"]
        print()
        print(f"endpoints with at least one match: {matched}")
        # The honest caveat. A clean result on an unreachable catalogue is not a
        # clean estate.
        if report["blocked"]:
            print(f"Note: {report['blocked']} of {report['total']} fingerprints "
                  f"could not be evaluated at all, so a low count here is not "
                  f"evidence of absence.")
        return EXIT_OK
    finally:
        conn.close()


def cmd_catalogue_validate(args) -> int:
    """Structural checks. Catches the mistakes that silently disable a check."""
    import collections
    import re

    import yaml

    from .ingest.fingerprint import GROUP_EXPOSURE

    cfg = load_config(args.config, args.data)
    path = cfg.config_dir / "fingerprints.yaml"
    if not path.exists():
        print("no fingerprints.yaml — nothing to validate")
        return EXIT_OK
    doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}

    problems: list[str] = []
    ids: collections.Counter = collections.Counter()
    MATCHERS = ("title", "tech", "cpe", "body", "favicon", "server", "port")

    sections = ("panels", "default_pages", "disclosure", "storage_exposure")
    total = 0
    for section in sections:
        for entry in doc.get(section) or []:
            total += 1
            eid = entry.get("id")
            if not eid:
                problems.append(f"{section}: an entry has no id")
                continue
            ids[eid] += 1

            if not any(k in entry for k in MATCHERS):
                # An entry with no matcher never fires, and looks like coverage.
                problems.append(f"{eid}: no matcher — it can never fire")

            for key in ("title", "body", "server"):
                for pattern in entry.get(key) or []:
                    text = str(pattern)
                    try:
                        re.compile(text)
                    except re.error as exc:
                        problems.append(f"{eid}: bad {key} regex {pattern!r}: {exc}")
                        continue

                    # A space-padded pipe is a literal separator in a page title,
                    # but a regex reads it as alternation. `Welcome | PRTG` matched
                    # the bare word "Welcome" and reported a default nginx page as
                    # a PRTG install.
                    if re.search(r"(?<!\\)\s\|\s|(?<!\\)\|\s|\s(?<!\\)\|", text) \
                            and "(" not in text:
                        problems.append(
                            f"{eid}: {key} pattern {pattern!r} has an unescaped "
                            f"space-padded '|' — as a regex that is alternation, so "
                            f"it matches each side on its own. Escape it as '\\|'.")

                    # A two- or three-character alternative matches inside ordinary
                    # words and prose. Anchor it.
                    for alt in text.split("|"):
                        bare = alt.strip().strip("^$")
                        if 0 < len(bare) < 4 and bare.isalnum():
                            problems.append(
                                f"{eid}: {key} alternative {alt!r} is too short to "
                                f"be distinctive — anchor it with \\b")

            if section == "panels":
                group = entry.get("group")
                if group not in GROUP_EXPOSURE:
                    problems.append(
                        f"{eid}: group {group!r} has no severity mapping, so a "
                        f"match would score nothing")
                # Matched by platform name alone is the WordPress trap.
                if (entry.get("tech") or entry.get("cpe")) \
                        and not entry.get("title") \
                        and not entry.get("require_title"):
                    problems.append(
                        f"{eid}: matches on technology with no title — verify this "
                        f"cannot fire on a site that merely runs the platform")

    for eid, count in ids.items():
        if count > 1:
            problems.append(f"{eid}: duplicate id ({count} entries)")

    print(f"checked {total} fingerprint(s)")
    if problems:
        print()
        for problem in problems:
            print(f"  - {problem}")
        print()
        print(f"{len(problems)} problem(s)", file=sys.stderr)
        return EXIT_ERROR
    print("catalogue is valid")
    return EXIT_OK


def cmd_catalogue_list(args) -> int:
    from .ingest import fingerprint

    cfg = load_config(args.config, args.data)
    catalogue = fingerprint.load_catalogue(cfg.config_dir)
    rows = []
    for matcher in catalogue.all_matchers():
        if args.group and matcher.group != args.group:
            continue
        signals = [name for name, value in (
            ("title", matcher.title), ("tech", matcher.tech), ("cpe", matcher.cpe),
            ("body", matcher.body), ("favicon", matcher.favicon),
            ("server", matcher.server), ("port", matcher.ports),
        ) if value]
        rows.append({
            "id": matcher.id,
            "product": matcher.product or matcher.label,
            "group": matcher.group,
            "confidence": matcher.confidence,
            "signals": ",".join(signals),
        })
    print(_fmt_table(rows, ["id", "product", "group", "confidence", "signals"]))
    print()
    print(f"{len(rows)} fingerprint(s)")
    return EXIT_OK


def cmd_suggest(args) -> int:
    from .ingest import quality

    cfg = load_config(args.config, args.data)
    conn = connect(cfg.db_path)
    try:
        from .api._db import resolve_run as _resolve
        run = _resolve(conn, args.run, args.project)
        if not run:
            print("no runs ingested yet", file=sys.stderr)
            return EXIT_STORE
        census = [
            dict(r) for r in conn.execute(
                "SELECT column_name, non_empty, total, fill_pct, sample "
                "FROM run_columns WHERE run_id = ?", (run["id"],)
            )
        ]
    finally:
        conn.close()

    empty = [c["column_name"] for c in census if c["fill_pct"] == 0.0]
    print(f"run {run['run_key']}: {len(empty)} of {len(census)} source columns are empty")
    print()
    for s in quality.suggest_httpx_flags(census):
        print(f"{s['flag']}")
        print(f"  unlocks: {s['unlocks']}")
        if s["empty_columns"]:
            print(f"  fills:   {', '.join(s['empty_columns'])}")
        print()
    print("suggested command for the next scan:")
    print(f"  {quality.recommended_command(census)}")
    return EXIT_OK


# ── Parser ──────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="frogscope",
        description="Turn recurring httpx scans into a queryable attack-surface "
                    "dashboard.",
    )
    p.add_argument("--config", help="config directory (default ./config)")
    p.add_argument("--data", help="data directory (default ./data)")
    sub = p.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("init", help="create the data directory and database")
    sp.set_defaults(func=cmd_init)

    sp = sub.add_parser("doctor", help="check config, dependencies, and database")
    sp.set_defaults(func=cmd_doctor)

    sp = sub.add_parser("config", help="show resolved configuration")
    sp.set_defaults(func=cmd_config)

    sp = sub.add_parser("validate", help="analyse a file without writing anything")
    sp.add_argument("file")
    sp.set_defaults(func=cmd_validate)

    sp = sub.add_parser("ingest", help="ingest one or more httpx output files")
    sp.add_argument("files", nargs="+")
    sp.add_argument("--project", default="default")
    sp.add_argument("--project-name")
    sp.add_argument("--label")
    sp.add_argument("--kind", default="adhoc",
                    choices=["baseline", "weekly", "monthly", "adhoc"])
    sp.add_argument("--force", action="store_true",
                    help="ingest even if identical content is already stored")
    sp.add_argument("--allow-incomplete", action="store_true",
                    help="ingest even if the scan looks like it is still running")
    sp.add_argument("--allow-drift", action="store_true",
                    help="ingest even if the endpoint count changed dramatically")
    sp.add_argument("--no-archive", action="store_true",
                    help="do not keep a gzipped copy of the source file")
    sp.add_argument("--correlation",
                    help="path to a correlation.json sidecar (from a "
                         "correlated `frogscope scan`), attached to every "
                         "file ingested in this run")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_ingest)

    sp = sub.add_parser(
        "scan", help="run a live scan (domains, IP addresses, or CIDR ranges)")
    sp.add_argument("targets", nargs="+",
                    help="domains, IP addresses, and/or CIDR ranges, mixed freely")
    sp.add_argument("--project", default="default")
    sp.add_argument("--project-name")
    sp.add_argument("--label")
    sp.add_argument("--profile", default=None,
                    help=f"port profile (default: {'/'.join(scan_options.PORT_PROFILES)})")
    sp.add_argument("--no-subfinder", action="store_true",
                    help="probe the given names directly, skip subdomain discovery")
    sp.add_argument("--rate-limit", type=int)
    sp.add_argument("--threads", type=int)
    sp.add_argument("--timeout", type=int)
    sp.add_argument("--retries", type=int)
    sp.add_argument("--approve-hosts", type=int, default=0,
                    help="pre-approve probing up to this many hosts, past the "
                         "confirmation threshold")
    sp.add_argument("--authorised", action="store_true",
                    help="confirm you are authorised to scan these targets "
                         "(required — this sends real traffic)")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_scan)

    sp = sub.add_parser("runs", help="list ingested runs")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_runs)

    sp = sub.add_parser("query", help="query endpoints from the terminal")
    sp.add_argument("--run", default="latest")
    sp.add_argument("--project")
    sp.add_argument("--filter", action="append",
                    help="e.g. 'origin_exposed=true,env!=prod' or 'response_ms>=500'")
    sp.add_argument("--search")
    sp.add_argument("--columns")
    sp.add_argument("--sort")
    sp.add_argument("--limit", type=int, default=50)
    sp.add_argument("--format", default="table", choices=["table", "csv", "json"])
    sp.set_defaults(func=cmd_query)

    sp = sub.add_parser("serve", help="run the dashboard")
    sp.add_argument("--host", default="127.0.0.1")
    sp.add_argument("--port", type=int, default=8099)
    sp.add_argument("--open", action="store_true")
    sp.add_argument("--reload", action="store_true")
    sp.set_defaults(func=cmd_serve)

    sp = sub.add_parser("gate",
                        help="fail with exit code 5 when a threshold is breached")
    sp.add_argument("--fail-on", required=True,
                    help="each clause is a FAILURE condition, e.g. "
                         "'critical>0,added>10,posture_index_host<40' means fail "
                         "when there is any critical finding, more than 10 new "
                         "assets, or the posture index drops below 40")
    sp.add_argument("--run", default="latest")
    sp.add_argument("--project")
    sp.set_defaults(func=cmd_gate)

    sp = sub.add_parser("inventory", help="technology, infrastructure, auth, takeover")
    sp.add_argument("kind", choices=["technology", "infrastructure", "auth",
                                     "takeover"])
    sp.add_argument("--run", default="latest")
    sp.add_argument("--project")
    sp.add_argument("--limit", type=int, default=30)
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_inventory)

    sp = sub.add_parser(
        "verify",
        help="live verification of takeover candidates (the only command that "
             "sends network traffic)")
    sp.add_argument("--takeover", action="store_true",
                    help="accepted for clarity; verification is takeover-only")
    sp.add_argument("--run", default="latest")
    sp.add_argument("--project")
    sp.add_argument("--limit", type=int)
    sp.add_argument("--timeout", type=float, default=8.0)
    sp.add_argument("--delay", type=float, default=0.5,
                    help="seconds between hosts")
    sp.add_argument("--dns-only", action="store_true",
                    help="resolve DNS but make no HTTP request")
    sp.add_argument("--yes", action="store_true",
                    help="skip the confirmation prompt")
    sp.add_argument("--fail-on-confirmed", action="store_true",
                    help="exit 5 when a takeover is confirmed, for CI")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_verify)

    sp = sub.add_parser("watch", help="auto-ingest httpx output dropped in a folder")
    sp.add_argument("folder")
    sp.add_argument("--project", default="default")
    sp.add_argument("--project-name")
    sp.add_argument("--label")
    sp.add_argument("--kind", default="adhoc",
                    choices=["baseline", "weekly", "monthly", "adhoc"])
    sp.add_argument("--interval", type=float, default=30.0)
    sp.add_argument("--once", action="store_true")
    sp.add_argument("--allow-incomplete", action="store_true")
    sp.add_argument("--allow-drift", action="store_true")
    sp.add_argument("--notify", action="store_true",
                    help="send notifications after each successful ingest")
    sp.set_defaults(func=cmd_watch)

    sp = sub.add_parser(
        "notify",
        help="alert on new critical findings (previews unless --send)")
    sp.add_argument("--run", default="latest")
    sp.add_argument("--project")
    sp.add_argument("--send", action="store_true",
                    help="actually deliver; without it this only previews")
    sp.add_argument("--target", action="append",
                    help="limit to named targets (repeatable)")
    sp.add_argument("--resend", action="store_true",
                    help="ignore the ledger and re-send items already sent")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_notify)

    sp = sub.add_parser("export-html",
                        help="offline single-file HTML, works with no network")
    sp.add_argument("--run", default="latest")
    sp.add_argument("--project")
    sp.add_argument("--out")
    sp.add_argument("--redact", action="store_true",
                    help="pseudonymise hostnames and addresses")
    sp.set_defaults(func=cmd_export_html)

    sp = sub.add_parser("workbook", help="multi-sheet XLSX export")
    sp.add_argument("--run", default="latest")
    sp.add_argument("--project")
    sp.add_argument("--out")
    sp.add_argument("--redact", action="store_true",
                    help="pseudonymise hostnames and addresses")
    sp.set_defaults(func=cmd_workbook)

    sp = sub.add_parser("trends", help="metric movement across runs")
    sp.add_argument("--project")
    sp.add_argument("--metric")
    sp.add_argument("--dim", default="all")
    sp.add_argument("--limit", type=int, default=12)
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_trends)

    sp = sub.add_parser("reindex",
                        help="recompute diffs and metrics in chronological order")
    sp.set_defaults(func=cmd_reindex)

    sp = sub.add_parser("report", help="executive summary to stdout or Markdown")
    sp.add_argument("--run", default="latest")
    sp.add_argument("--project")
    sp.add_argument("--format", default="text",
                    choices=["text", "markdown", "json"])
    sp.set_defaults(func=cmd_report)

    sp = sub.add_parser("score", help="scoring tools")
    score_sub = sp.add_subparsers(dest="score_action", required=True)
    sp2 = score_sub.add_parser("explain", help="full scoring trace for one endpoint")
    sp2.add_argument("endpoint", help="host:port")
    sp2.add_argument("--run", default="latest")
    sp2.add_argument("--project")
    sp2.set_defaults(func=cmd_score_explain)

    sp = sub.add_parser("rules", help="inspect and validate the rule set")
    sp.add_argument("action", nargs="?", default="list",
                    choices=["list", "validate", "explain", "coverage"])
    sp.add_argument("rule_id", nargs="?")
    sp.add_argument("--run", default="latest")
    sp.add_argument("--project")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_rules)

    sp = sub.add_parser("findings", help="list findings")
    sp.add_argument("--project")
    sp.add_argument("--severity", action="append",
                    choices=["critical", "high", "medium", "low", "info"])
    sp.add_argument("--status", choices=["open", "ack", "resolved"])
    sp.add_argument("--rule")
    sp.add_argument("--limit", type=int, default=40)
    sp.add_argument("--format", default="table", choices=["table", "markdown"])
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_findings)

    sp = sub.add_parser("rescore",
                        help="re-derive scores from archived sources after a weight change")
    sp.add_argument("--run", default="all")
    sp.set_defaults(func=cmd_rescore)

    sp = sub.add_parser("store", help="maintenance on the stored data")
    store_sub = sp.add_subparsers(dest="store_cmd", required=True)
    sp2 = store_sub.add_parser(
        "compact", help="prune archived source files, keeping the newest N")
    sp2.add_argument("--keep-last", type=int, default=12)
    sp2.add_argument("--project")
    sp2.add_argument("--dry-run", action="store_true")
    sp2.set_defaults(func=cmd_store_compact)
    sp2 = store_sub.add_parser("verify", help="check the store for inconsistency")
    sp2.set_defaults(func=cmd_store_verify)

    sp = sub.add_parser(
        "catalogue",
        help="detection catalogue: provenance, coverage, and validation")
    cat_sub = sp.add_subparsers(dest="catalogue_cmd", required=True)
    sp2 = cat_sub.add_parser("status", help="what was reviewed, when, and is it due")
    sp2.set_defaults(func=cmd_catalogue_status)
    sp2 = cat_sub.add_parser("coverage",
                             help="how much of the catalogue this scan can reach")
    sp2.add_argument("--run", default="latest")
    sp2.add_argument("--project")
    sp2.set_defaults(func=cmd_catalogue_coverage)
    sp2 = cat_sub.add_parser("validate", help="structural checks on the catalogue")
    sp2.set_defaults(func=cmd_catalogue_validate)
    sp2 = cat_sub.add_parser("list", help="every fingerprint in the catalogue")
    sp2.add_argument("--group")
    sp2.set_defaults(func=cmd_catalogue_list)

    sp = sub.add_parser("suggest-httpx",
                        help="recommend httpx flags based on empty columns")
    sp.add_argument("--run", default="latest")
    sp.add_argument("--project")
    sp.set_defaults(func=cmd_suggest)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except FileNotFoundError as exc:
        print(f"file not found: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        return EXIT_ERROR


# ── Phase 2: scoring and findings ───────────────────────────────────────────

def _severity_glyph(severity: str) -> str:
    return {"critical": "!!", "high": "! ", "medium": "~ ",
            "low": ". ", "info": "  "}.get(severity, "  ")


def cmd_score_explain(args) -> int:
    """Print the full scoring trace for one endpoint.

    The same waterfall the drawer renders. This is the answer to "why 72?", and
    it has to be reproducible from the terminal or nobody will trust the number.
    """
    import json as _json

    cfg = load_config(args.config, args.data)
    conn = connect(cfg.db_path)
    try:
        from .api._db import resolve_run as _resolve
        run = _resolve(conn, args.run, args.project)
        if not run:
            print("no runs ingested yet", file=sys.stderr)
            return EXIT_STORE

        row = conn.execute(
            "SELECT * FROM asset_scores WHERE run_id = ? AND endpoint_key = ?",
            (run["id"], args.endpoint),
        ).fetchone()
        if row is None:
            like = conn.execute(
                "SELECT endpoint_key FROM asset_scores WHERE run_id = ? "
                "AND endpoint_key LIKE ? LIMIT 8",
                (run["id"], f"%{args.endpoint}%"),
            ).fetchall()
            print(f"no endpoint {args.endpoint!r} in run {run['run_key']}",
                  file=sys.stderr)
            if like:
                print("did you mean:", file=sys.stderr)
                for candidate in like:
                    print(f"  {candidate['endpoint_key']}", file=sys.stderr)
            return EXIT_USAGE
    finally:
        conn.close()

    if row["excluded"]:
        print(f"{args.endpoint}: not scored")
        print(f"  excluded by {row['excluded_by']}")
        return EXIT_OK

    contributions = _json.loads(row["contributions_json"] or "[]")
    modifiers = _json.loads(row["modifiers_json"] or "[]")
    skipped = _json.loads(row["skipped_json"] or "[]")

    print(f"{args.endpoint}   run {run['run_key']}")
    print()
    print(f"  final score   {row['score']}/100   band {row['band']}")
    if row["floored_from"]:
        print(f"                raised from {row['floored_from']} by the severity "
              f"floor, because a critical rule fired and nothing mitigated it")
    print(f"  worst issue   {row['worst_severity'] or 'none'}")
    print(f"  buckets       exposure {row['exposure']}  hygiene {row['hygiene']}"
          f"  sensitivity {row['sensitivity']}")
    print(f"  data coverage {int((row['coverage'] or 0) * 100)}% "
          f"({row['confidence']} confidence)")
    print()

    print("  how the score was built")
    print(f"  {'':>6}  {'':2} {'rule':<26} {'bucket':<14} note")
    for entry in contributions:
        notes = []
        if entry["family_discounted"]:
            notes.append("family sibling x0.3")
        if entry["capped"]:
            notes.append("bucket cap reached")
        if entry["family"] == "positive":
            notes.append("positive control")
        print(f"  {entry['points_applied']:+5d}  {_severity_glyph(entry['severity'])} "
              f"{entry['rule_id']:<26} {entry['bucket']:<14} "
              f"{'; '.join(notes)}")
        if entry["points_raw"] != entry["points_applied"]:
            print(f"  {'':>6}  {'':2} {'':<26} {'':<14} "
                  f"(raw weight {entry['points_raw']})")

    print(f"  {'-' * 68}")
    print(f"  {row['raw_score']:5d}   subtotal after bucket caps")
    for modifier in modifiers:
        print(f"  x{modifier['factor']:<5}  {modifier['id']}")
        print(f"  {'':>7} {modifier['reason']}")
    if modifiers:
        print(f"  {row['score']:5d}   final")
    print()

    print("  why each rule fired")
    for entry in contributions:
        if entry["family"] == "positive":
            continue
        print(f"  {_severity_glyph(entry['severity'])}{entry['rule_id']} "
              f"({entry['severity']}, {entry['confidence']})")
        if entry["why"]:
            print(f"      {entry['why']}")
        if entry["evidence"]:
            observed = ", ".join(f"{k}={v!r}" for k, v in entry["evidence"].items())
            print(f"      observed: {observed}")
        if entry["remediation"]:
            print(f"      fix: {entry['remediation']}")
        print()

    if skipped:
        print("  rules that could not be evaluated")
        for entry in skipped:
            print(f"    {entry['rule_id']:<26} needs "
                  f"{', '.join(entry['missing_fields'])}")
        print()
        print("  Run `frogscope suggest-httpx` for the flags that would fill these in.")

    return EXIT_OK


def cmd_rules(args) -> int:
    from .scoring.rules import RuleError, load_ruleset, rules_fingerprint

    cfg = load_config(args.config, args.data)
    try:
        ruleset = load_ruleset(cfg.config_dir)
    except RuleError as exc:
        print(f"rules are invalid:\n{exc}", file=sys.stderr)
        return EXIT_ERROR

    if args.action == "validate":
        print(f"rules valid: {len(ruleset.rules)} rules, "
              f"{len(ruleset.modifiers)} modifiers, "
              f"{len(ruleset.exclusions)} exclusions")
        print(f"fingerprint {rules_fingerprint(ruleset)}")
        return EXIT_OK

    if args.action == "list":
        rows = [
            {
                "id": r.id, "severity": r.severity, "family": r.family,
                "bucket": r.bucket, "points": r.points if r.points is not None
                          else ("map" if r.map_spec else "scaled"),
                "confidence": r.confidence,
                "inert": "yes" if r.requires_fields else "",
                "title": r.title,
            }
            for r in sorted(ruleset.rules,
                            key=lambda r: (SEVERITY_SORT.get(r.severity, 9), r.id))
        ]
        if args.json:
            print(json.dumps(ruleset.as_dict(), indent=2))
        else:
            print(_fmt_table(rows, ["id", "severity", "confidence", "family",
                                    "bucket", "points", "inert", "title"]))
        return EXIT_OK

    if args.action == "explain":
        rule = ruleset.by_id(args.rule_id or "")
        if rule is None:
            print(f"no rule {args.rule_id!r}", file=sys.stderr)
            return EXIT_USAGE
        detail = rule.as_dict()
        print(f"{rule.id}  ({rule.severity}, {rule.confidence} confidence)")
        print(f"  title       {rule.title}")
        print(f"  family      {rule.family}   bucket {rule.bucket}")
        print(f"  weight      {detail['points'] or detail['map'] or detail['scaled']}")
        print(f"  fires when  {detail['condition']}")
        if rule.requires_fields:
            print(f"  inert       needs {', '.join(rule.requires_fields)} — "
                  f"skipped, never scored as a problem, until that data exists")
        print()
        print(f"  why         {rule.why}")
        print(f"  for an exec {rule.exec_line}")
        print(f"  fix         {rule.remediation}")
        return EXIT_OK

    # coverage
    conn = connect(cfg.db_path)
    try:
        from .api._db import resolve_run as _resolve
        run = _resolve(conn, args.run, args.project)
        if not run:
            print("no runs ingested yet", file=sys.stderr)
            return EXIT_STORE

        total = conn.execute(
            "SELECT COUNT(*) n FROM asset_scores WHERE run_id = ? AND excluded = 0",
            (run["id"],)).fetchone()["n"]
        bands = {
            r["band"]: r["n"] for r in conn.execute(
                "SELECT band, COUNT(*) n FROM asset_scores WHERE run_id = ? "
                "AND excluded = 0 GROUP BY 1", (run["id"],))
        }
        fired = {
            r["rule_id"]: r["n"] for r in conn.execute(
                "SELECT rule_id, COUNT(*) n FROM findings WHERE last_seen_run_id = ? "
                "GROUP BY 1", (run["id"],))
        }
    finally:
        conn.close()

    print(f"run {run['run_key']}   {total} scored endpoints")
    print()
    print("band distribution")
    warnings: list[str] = []
    for band in [b["name"] for b in ruleset.bands]:
        count = bands.get(band, 0)
        share = (100 * count / total) if total else 0
        bar = "#" * int(share / 2)
        print(f"  {band:<9} {count:5d}  {share:5.1f}%  {bar}")
        if count == 0:
            warnings.append(
                f"band {band!r} is empty — either nothing is that bad, or its "
                f"threshold ({next(b['min'] for b in ruleset.bands if b['name'] == band)}) "
                f"is unreachable with the current weights"
            )
        elif share > 50:
            warnings.append(
                f"band {band!r} holds {share:.0f}% of the estate — a band that "
                f"swallows the majority carries no information"
            )

    print()
    print("rules by endpoints affected")
    silent = []
    for rule in sorted(ruleset.rules, key=lambda r: -fired.get(r.id, 0)):
        if rule.family == "positive":
            continue
        count = fired.get(rule.id, 0)
        if count == 0:
            silent.append(rule)
            continue
        share = (100 * count / total) if total else 0
        print(f"  {count:5d}  {share:5.1f}%  {rule.id}")
        if share > 95:
            warnings.append(
                f"rule {rule.id!r} fires on {share:.0f}% of endpoints — a rule "
                f"that fires on everything is mis-modelled, not a finding"
            )

    if silent:
        print()
        print("rules that never fired")
        for rule in silent:
            reason = (f"inert, needs {', '.join(rule.requires_fields)}"
                      if rule.requires_fields else "no match in this run")
            print(f"  {rule.id:<26} {reason}")

    if warnings:
        print()
        print("calibration warnings")
        for warning in warnings:
            print(f"  ! {warning}")

    return EXIT_OK


SEVERITY_SORT = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def cmd_findings(args) -> int:
    cfg = load_config(args.config, args.data)
    conn = connect(cfg.db_path)
    try:
        sql = (
            "SELECT f.severity, f.confidence, f.rule_id, f.asset_key, f.title, "
            "f.status, f.detail_json FROM findings f "
            "JOIN projects p ON p.id = f.project_id WHERE 1=1"
        )
        params: list = []
        if args.project:
            sql += " AND p.slug = ?"
            params.append(args.project)
        if args.severity:
            placeholders = ",".join("?" for _ in args.severity)
            sql += f" AND f.severity IN ({placeholders})"
            params.extend(args.severity)
        if args.status:
            sql += " AND f.status = ?"
            params.append(args.status)
        if args.rule:
            sql += " AND f.rule_id = ?"
            params.append(args.rule)
        rows = [dict(r) for r in conn.execute(sql, params)]
    finally:
        conn.close()

    rows.sort(key=lambda r: (SEVERITY_SORT.get(r["severity"], 9), r["rule_id"],
                             r["asset_key"]))
    rows = rows[: args.limit]

    for row in rows:
        detail = json.loads(row.pop("detail_json") or "{}")
        row["endpoints"] = detail.get("endpoint_count", 0)
        row["score"] = detail.get("max_score", 0)

    if args.json:
        print(json.dumps(rows, indent=2))
    elif args.format == "markdown":
        print("| Severity | Rule | Host | Endpoints | Title |")
        print("|---|---|---|---|---|")
        for row in rows:
            print(f"| {row['severity']} | {row['rule_id']} | {row['asset_key']} "
                  f"| {row['endpoints']} | {row['title']} |")
    else:
        print(_fmt_table(rows, ["severity", "confidence", "rule_id", "asset_key",
                                "endpoints", "score", "status", "title"]))
        print()
        print(f"{len(rows)} findings shown")
    return EXIT_OK


def cmd_rescore(args) -> int:
    """Re-derive scores for stored runs after a weight change.

    Reads the archived source file rather than the database, so improved
    enrichment logic is picked up too — better logic later means re-deriving
    history, not losing it.
    """
    from .ingest import pipeline

    cfg = load_config(args.config, args.data)
    conn = connect(cfg.db_path)
    try:
        migrate(conn)
        rows = conn.execute(
            "SELECT r.id, r.run_key, r.label, r.source_file, p.slug "
            "FROM runs r JOIN projects p ON p.id = r.project_id "
            "WHERE r.duplicate_of IS NULL ORDER BY COALESCE(r.started_at,''), r.id"
        ).fetchall()
        if args.run and args.run != "all":
            rows = [r for r in rows if str(r["id"]) == str(args.run)
                    or r["run_key"] == args.run]

        if not rows:
            print("nothing to rescore", file=sys.stderr)
            return EXIT_STORE

        rescored = 0
        for row in rows:
            archive = cfg.raw_dir / f"{row['run_key']}.csv.gz"
            if not archive.exists():
                print(f"  {row['run_key']}: source archive missing, skipped "
                      f"(was it ingested with --no-archive?)")
                continue
            store.delete_run(conn, row["id"])
            conn.commit()
            result = pipeline.ingest(
                conn, cfg, archive, project=row["slug"], label=row["label"],
                allow_incomplete=True, allow_drift=True, keep_raw=False,
            )
            print(f"  {row['run_key']} -> {result.run_key}: "
                  f"{result.endpoint_count} endpoints rescored")
            rescored += 1
    finally:
        conn.close()

    print(f"rescored {rescored} run(s)")
    return EXIT_OK


# ── Phase 3: executive report ───────────────────────────────────────────────

def cmd_report(args) -> int:
    """Executive summary to stdout or Markdown.

    The same numbers and sentences the Executive page shows, so a weekly email
    or a ticket comment needs no browser.
    """
    from .analytics import kpis, narrative
    from .scoring.rules import load_ruleset

    cfg = load_config(args.config, args.data)
    conn = connect(cfg.db_path)
    try:
        from .api._db import resolve_run as _resolve
        run = _resolve(conn, args.run, args.project)
        if not run:
            print("no runs ingested yet", file=sys.stderr)
            return EXIT_STORE
        data = kpis.build(conn, run, load_ruleset(cfg.config_dir))
        story = narrative.build(data)
    finally:
        conn.close()

    if args.format == "json":
        print(json.dumps({**data, "narrative": story}, indent=2, default=str))
        return EXIT_OK

    md = args.format == "markdown"
    h1 = "# " if md else ""
    h2 = "## " if md else ""
    bullet = "- " if md else "  - "
    posture = data["posture"]
    surface = data["surface"]

    print(f"{h1}External attack surface")
    print()
    print(f"{data['run']['label'] or data['run']['run_key']} · "
          f"scanned {data['run']['started_at']}")
    if data["run"]["incomplete"]:
        print()
        print("**This scan was flagged as possibly incomplete when ingested.**"
              if md else
              "! This scan was flagged as possibly incomplete when ingested.")
    print()
    print(story["headline"])
    if story["verdict"]:
        print(story["verdict"])
    print()

    print(f"{h2}Posture")
    print()
    rows = [
        ("Hosts reviewed", surface["hosts"]),
        ("Distinct services", surface["real_endpoints"]),
        ("Hosts needing attention", f"{posture['needs_attention']} "
                                    f"({posture['needs_attention_pct']}%)"),
        ("Hosts with nothing flagged", posture["clean"]),
        ("Open findings", data["findings"]["total"]),
        ("Posture index (by host)", f"{posture['index']}/100"),
        ("Posture index (by endpoint)",
         f"{data['endpoint_index'].get('index', '—')}/100"),
    ]
    if md:
        print("| Measure | Value |")
        print("|---|---|")
        for label, value in rows:
            print(f"| {label} | {value} |")
    else:
        for label, value in rows:
            print(f"  {label:<30} {value}")
    print()

    print(f"{h2}What to fix, most widespread first")
    print()
    for theme in story["themes"]:
        print(f"{bullet}**{theme['severity']}** — {theme['sentence']}"
              if md else
              f"{bullet}[{theme['severity']}] {theme['sentence']}")
        if theme["remediation"]:
            print(f"{'  ' if md else '    '}{theme['remediation']}")
        if theme["confidence_note"]:
            print(f"{'  ' if md else '    '}{theme['confidence_note']}")
    print()

    print(f"{h2}Context")
    print()
    for note in story["notes"]:
        print(f"{bullet}{note}")
    print()

    print(f"{h2}Highest-risk hosts")
    print()
    if md:
        print("| Host | Worst issue | Score | Findings |")
        print("|---|---|---|---|")
        for host in data["top_hosts"]:
            worst = host["worst_finding"]["title"] if host["worst_finding"] else "—"
            print(f"| `{host['host']}` | {host['worst_severity'] or '—'}: {worst} "
                  f"| {host['risk_score']} | {host['finding_count']} |")
    else:
        for host in data["top_hosts"]:
            worst = host["worst_finding"]["title"] if host["worst_finding"] else "—"
            print(f"  {host['risk_score']:3d}  {host['host']:<44} "
                  f"{host['worst_severity'] or '':<9} {worst}")
    print()

    print(f"{h2}What this scan could not see")
    print()
    for caveat in data["caveats"]:
        print(f"{bullet}{caveat}")

    if not data["comparison"]["available"]:
        print()
        print(f"{bullet}{data['comparison']['reason']}")

    return EXIT_OK


def cmd_trends(args) -> int:
    from .ingest import timeseries

    cfg = load_config(args.config, args.data)
    conn = connect(cfg.db_path)
    try:
        from .api._db import resolve_run as _resolve
        run = _resolve(conn, "latest", args.project)
        if not run:
            print("no runs ingested yet", file=sys.stderr)
            return EXIT_STORE
        project_id = run["project_id"]
        if args.metric:
            points = timeseries.series(conn, project_id, args.metric,
                                       args.dim, args.limit)
            rows = [{"run": p["label"] or p["run_key"], "when": p["started_at"],
                     "value": p["value"]} for p in points]
            if args.json:
                print(json.dumps(points, indent=2))
            else:
                print(_fmt_table(rows, ["run", "when", "value"]))
            return EXIT_OK

        labels = {m["key"]: m.get("label", m["key"])
                  for m in (cfg.diff.get("metrics") or [])}
        available = timeseries.available_metrics(conn, project_id)
        headline = [m["metric"] for m in available if m["dim"] == "all"]
        rows = []
        for name in headline:
            points = timeseries.series(conn, project_id, name, "all", args.limit)
            if len(points) < 1:
                continue
            values = [p["value"] for p in points]
            first, last = values[0], values[-1]
            rows.append({
                "metric": labels.get(name, name),
                "series": " → ".join(f"{v:g}" for v in values[-6:]),
                "change": (f"{last - first:+g}" if len(values) > 1 else "—"),
            })
    finally:
        conn.close()

    if args.json:
        print(json.dumps(rows, indent=2))
    else:
        print(_fmt_table(rows, ["metric", "series", "change"]))
        print()
        print("Change is last minus first over the window shown.")
    return EXIT_OK


def cmd_reindex(args) -> int:
    """Recompute diffs and metrics for every run in chronological order.

    Needed after backfilling an older scan, which changes which run precedes
    which — the stored diffs would otherwise describe the wrong comparison.
    """
    from .ingest import diff as diff_mod
    from .ingest import timeseries

    cfg = load_config(args.config, args.data)
    conn = connect(cfg.db_path)
    try:
        migrate(conn)
        projects = conn.execute("SELECT id, slug FROM projects").fetchall()
        for project in projects:
            runs = conn.execute(
                "SELECT * FROM runs WHERE project_id = ? AND duplicate_of IS NULL "
                "ORDER BY COALESCE(started_at,''), id", (project["id"],)
            ).fetchall()
            if not runs:
                continue
            print(f"{project['slug']}: {len(runs)} run(s)")
            # Replaying appends to presence, so it has to start clean or every
            # asset looks previously seen and `added` collapses to zero.
            diff_mod.reset_presence(conn, project["id"])
            conn.execute(
                "DELETE FROM asset_attr_history WHERE project_id = ?",
                (project["id"],))
            previous = None
            for run in runs:
                summary = diff_mod.diff_runs(conn, project["id"], run["id"],
                                             previous, cfg.diff)
                fresh = conn.execute("SELECT * FROM runs WHERE id = ?",
                                     (run["id"],)).fetchone()
                timeseries.materialise(conn, run["id"], fresh)
                label = run["label"] or run["run_key"]
                if summary.get("baseline"):
                    print(f"  {label}: baseline")
                else:
                    print(f"  {label}: +{summary['added']} "
                          f"-{summary['removed']} ~{summary['modified']}")
                previous = run["id"]
            conn.commit()
    finally:
        conn.close()
    return EXIT_OK


# ── Phase 5: gating, inventories, workbook ──────────────────────────────────

def _parse_fail_on(spec: str) -> list[tuple[str, str, float]]:
    """'critical>0,added_high>3' -> [(metric, op, threshold)]."""
    out: list[tuple[str, str, float]] = []
    for clause in (spec or "").split(","):
        clause = clause.strip()
        if not clause:
            continue
        match = re.match(r"^([a-z_]+)\s*(>=|<=|>|<|=)\s*(-?\d+(?:\.\d+)?)$",
                         clause, re.I)
        if not match:
            raise ValueError(
                f"cannot parse {clause!r}. Expected something like "
                f"'critical>0' or 'posture_index_host<40'")
        out.append((match.group(1).lower(), match.group(2), float(match.group(3))))
    return out


def evaluate_gate(conn, run, spec: str) -> tuple[bool, list[str]]:
    """Check threshold clauses against a run. Returns (breached, messages).

    For cron and CI: the weekly job should stay quiet unless posture actually
    worsened, and a non-zero exit is what makes that possible.
    """
    checks = _parse_fail_on(spec)
    if not checks:
        return False, []

    risk = json.loads(run["risk_summary_json"] or "{}") or {}
    diff = json.loads(run["diff_json"] or "{}") or {}
    severities = risk.get("by_severity") or {}

    values: dict[str, float] = {
        "critical": severities.get("critical", 0),
        "high": severities.get("high", 0),
        "medium": severities.get("medium", 0),
        "low": severities.get("low", 0),
        "findings": risk.get("total", 0),
        "added": diff.get("added", 0),
        "removed": diff.get("removed", 0),
        "modified": diff.get("modified", 0),
        "worse": diff.get("worse", 0),
        "better": diff.get("better", 0),
    }
    for metric in ("posture_index_host", "hosts_needing_attention",
                   "no_waf_hosts", "origin_exposed_hosts", "eol_hosts",
                   "takeover_candidates"):
        row = conn.execute(
            "SELECT value FROM run_metrics WHERE run_id = ? AND metric = ? "
            "AND dim = 'all'", (run["id"], metric)).fetchone()
        if row:
            values[metric] = row["value"]

    breached = False
    messages: list[str] = []
    for metric, op, threshold in checks:
        if metric not in values:
            messages.append(
                f"unknown metric {metric!r} — available: "
                f"{', '.join(sorted(values))}")
            breached = True
            continue
        actual = values[metric]
        hit = {
            ">": actual > threshold, ">=": actual >= threshold,
            "<": actual < threshold, "<=": actual <= threshold,
            "=": actual == threshold,
        }[op]
        verdict = "BREACH" if hit else "ok"
        messages.append(f"{verdict}: {metric} {actual:g} {op} {threshold:g}")
        breached = breached or hit
    return breached, messages


def cmd_gate(args) -> int:
    cfg = load_config(args.config, args.data)
    conn = connect(cfg.db_path)
    try:
        from .api._db import resolve_run as _resolve
        run = _resolve(conn, args.run, args.project)
        if not run:
            print("no runs ingested yet", file=sys.stderr)
            return EXIT_STORE
        try:
            breached, messages = evaluate_gate(conn, run, args.fail_on)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return EXIT_USAGE
    finally:
        conn.close()

    print("Each clause states a FAILURE condition, so 'critical>0' means "
          "\"fail when there is at least one critical finding\".")
    print()
    for message in messages:
        print(f"  {message}")
    print()
    # Flushed before touching stderr, or the two streams interleave and the
    # verdict appears above the checks that produced it.
    sys.stdout.flush()
    if breached:
        print("thresholds breached", file=sys.stderr)
        return EXIT_THRESHOLD
    print("all thresholds satisfied")
    return EXIT_OK


def cmd_inventory(args) -> int:
    from .analytics import inventory as inv
    from .scoring.rules import load_ruleset

    cfg = load_config(args.config, args.data)
    conn = connect(cfg.db_path)
    try:
        from .api._db import resolve_run as _resolve
        run = _resolve(conn, args.run, args.project)
        if not run:
            print("no runs ingested yet", file=sys.stderr)
            return EXIT_STORE
        ruleset = load_ruleset(cfg.config_dir)

        if args.kind == "technology":
            data = inv.technology(conn, run["id"], ruleset.lifecycle)
            rows = [{"name": t["name"], "hosts": t["hosts"],
                     "versions": ", ".join(t["versions"]) or "—"}
                    for t in data["tech"][: args.limit]]
            columns = ["name", "hosts", "versions"]
        elif args.kind == "infrastructure":
            data = inv.infrastructure(conn, run["id"], ip_limit=args.limit)
            rows = [{"ip": a["ip"], "family": a["family"], "hosts": a["hosts"],
                     "providers": ", ".join(a["providers"]) or "—"}
                    for a in data["addresses"]]
            columns = ["ip", "family", "hosts", "providers"]
        elif args.kind == "auth":
            data = inv.auth_surfaces(conn, run["id"])
            rows = [{"type": g["type"], "hosts": g["hosts"],
                     "federated": g["federated"], "local": g["local"],
                     "no_waf": g["no_waf"], "over_http": g["over_http"]}
                    for g in data["groups"]]
            columns = ["type", "hosts", "federated", "local", "no_waf", "over_http"]
        else:
            data = inv.takeover(conn, run["id"], ruleset.takeover)
            rows = [{"grade": c["grade"], "host": c["host"],
                     "provider": c["provider"], "confidence": c["confidence"],
                     "status": c["status_code"], "health": c["origin_health"]}
                    for c in data["candidates"][: args.limit]]
            columns = ["grade", "host", "provider", "confidence", "status", "health"]
    finally:
        conn.close()

    if args.json:
        print(json.dumps(data, indent=2, default=str))
    else:
        print(_fmt_table(rows, columns))
        if args.kind == "takeover" and data["candidates"]:
            print()
            print("These are candidates, not confirmed takeovers. Verify with:")
            for command in data["candidates"][0]["verify_commands"]:
                print(f"  {command}")
    return EXIT_OK


def cmd_workbook(args) -> int:
    from .analytics import inventory as inv
    from .export.redact import Redactor
    from .export.xlsx import write_workbook
    from .query.catalog import Catalog
    from .query.facets import query_endpoints
    from .scoring.rules import load_ruleset

    cfg = load_config(args.config, args.data)
    conn = connect(cfg.db_path)
    catalog = Catalog(cfg)
    try:
        from .api._db import resolve_run as _resolve
        run = _resolve(conn, args.run, args.project)
        if not run:
            print("no runs ingested yet", file=sys.stderr)
            return EXIT_STORE
        ruleset = load_ruleset(cfg.config_dir)
        redactor = Redactor() if args.redact else None

        columns = catalog.default_visible()
        grid = query_endpoints(conn, run["id"], catalog, columns=columns, full=True)
        endpoint_rows = [
            {c: (", ".join(str(x) for x in r[c]) if isinstance(r.get(c), list)
                 else r.get(c)) for c in columns}
            for r in grid["rows"]
        ]
        tech = inv.technology(conn, run["id"], ruleset.lifecycle)
        infra = inv.infrastructure(conn, run["id"], ip_limit=1000)
        auth = inv.auth_surfaces(conn, run["id"])
        over = inv.takeover(conn, run["id"], ruleset.takeover)
    finally:
        conn.close()

    sheets: list[tuple[str, list[str], list[dict]]] = [
        ("Endpoints", columns, endpoint_rows),
        ("Technology", ["name", "hosts", "version_count"], tech["tech"]),
        ("End of life", ["name", "eol_date", "years_past_eol", "hosts"], tech["eol"]),
        ("Addresses", ["ip", "family", "hosts"], infra["addresses"]),
        ("Ports", ["port", "total", "real", "aliases", "artefacts"],
         infra["port_rows"]),
        ("Auth surfaces", ["endpoint_key", "type", "federated", "over_http"],
         [e for g in auth["groups"] for e in g["endpoints"]]),
        ("Takeover candidates", ["host", "grade", "provider", "confidence"],
         over["candidates"]),
    ]
    if redactor:
        sheets = [(n, c, [redactor.row(r) for r in rows]) for n, c, rows in sheets]
        sheets.append(("Redaction notice", ["note"], [{"note": redactor.note()}]))

    out = Path(args.out or f"{run['run_key']}"
                           f"{'-redacted' if args.redact else ''}.xlsx")
    write_workbook(out, sheets, title=f"frogscope — {run['run_key']}")
    print(f"wrote {out} ({out.stat().st_size // 1024} KB, {len(sheets)} sheets)")
    if redactor:
        print(redactor.note())
    return EXIT_OK


def cmd_export_html(args) -> int:
    """Offline single-file HTML export."""
    from .export import snapshot
    from .export.redact import Redactor
    from .scoring.rules import load_ruleset

    cfg = load_config(args.config, args.data)
    conn = connect(cfg.db_path)
    try:
        from .api._db import resolve_run as _resolve
        run = _resolve(conn, args.run, args.project)
        if not run:
            print("no runs ingested yet", file=sys.stderr)
            return EXIT_STORE
        ruleset = load_ruleset(cfg.config_dir)
        redactor = Redactor() if args.redact else None

        out = Path(args.out or
                   f"{run['run_key']}{'-redacted' if args.redact else ''}.html")
        size = snapshot.write(out, conn, cfg, run, ruleset, redactor=redactor)
    finally:
        conn.close()

    print(f"wrote {out} ({size // 1024} KB)")
    print("Opens by double-click with networking disabled: no CDN, no fonts, "
          "no API.")
    if redactor:
        print(redactor.note())
    return EXIT_OK


def cmd_notify(args) -> int:
    """Alert on what is new. Previews unless --send is passed."""
    from .scoring.rules import load_ruleset

    cfg = load_config(args.config, args.data)
    conn = connect(cfg.db_path)
    try:
        migrate(conn)
        from .api._db import resolve_run as _resolve
        run = _resolve(conn, args.run, args.project)
        if not run:
            print("no runs ingested yet", file=sys.stderr)
            return EXIT_STORE
        ruleset = load_ruleset(cfg.config_dir)
        return _notify_run(conn, cfg, run, ruleset,
                           send=args.send, only=args.target,
                           resend=args.resend, as_json=args.json)
    finally:
        conn.close()


def _notify_run(conn, cfg, run, ruleset, *, send: bool,
                only: list[str] | None = None, resend: bool = False,
                as_json: bool = False, quiet: bool = False) -> int:
    """Build the alert and, if asked, deliver it.

    Shared by `notify` and `watch --notify` so the two cannot drift apart in what
    they consider alertable.
    """
    from .notify import alerts as alerts_mod
    from .notify import sinks

    notify_cfg = alerts_mod.load_notify_config(cfg.config_dir)
    alert = alerts_mod.build_alert(conn, run, notify_cfg,
                                   takeover_cfg=ruleset.takeover,
                                   include_sent=resend)
    if as_json:
        print(json.dumps(alert.as_dict(), indent=2, default=str))
        return EXIT_OK

    if not quiet:
        print(sinks.text_summary(alert))
        print()

    targets, skipped = alerts_mod.active_targets(notify_cfg)
    if only:
        wanted = set(only)
        targets = [t for t in targets if t.get("name") in wanted]
    for reason in skipped:
        if not quiet:
            print(f"  skipped {reason}")

    if not alert.items:
        # Nothing to say, so say nothing. A weekly "all clear" trains people to
        # ignore the channel, and then the one real alert goes unread too.
        if not quiet:
            print("nothing new to report — no notification sent")
        return EXIT_OK

    if not notify_cfg.get("enabled"):
        print("notify.yaml has enabled: false — preview only, nothing sent")
        return EXIT_OK

    # Every hostname in the project, not just this run's: an alert's text can
    # name a host that was seen previously, and `Redactor` only rewrites names it
    # has been shown.
    known_hosts = [r["host"] for r in conn.execute(
        "SELECT DISTINCT e.host FROM endpoints e JOIN runs r ON r.id = e.run_id "
        "WHERE r.project_id = ?", (run["project_id"],))]

    if not send:
        print(f"{len(alert.items)} items ready for {len(targets)} target(s). "
              f"Pass --send to deliver.")
        for target in targets:
            delivered, message = sinks.deliver(
                alert, target, notify_cfg, data_dir=cfg.data_dir,
                known_hosts=known_hosts, dry_run=True)
            print(f"  {target.get('name')}: {message}")
        return EXIT_OK

    for target in targets:
        name = target.get("name") or target.get("kind") or "unnamed"
        delivered, message = sinks.deliver(alert, target, notify_cfg,
                                           data_dir=cfg.data_dir,
                                           known_hosts=known_hosts)
        # Recorded either way. A failure is written as `failed` rather than left
        # absent, so a retry is a deliberate act and a silent drop is visible.
        sinks.record(conn, alert, name, alert.items,
                     "sent" if delivered else "failed",
                     "" if delivered else message)
        print(f"  {name}: {'sent' if delivered else 'FAILED'} — {message}",
              file=sys.stdout if delivered else sys.stderr)
    return EXIT_OK


def cmd_verify(args) -> int:
    """Live verification of takeover candidates. Opt-in; sends packets."""
    from .scoring.rules import load_ruleset
    from .verify import takeover as verify_mod

    cfg = load_config(args.config, args.data)
    conn = connect(cfg.db_path)
    try:
        migrate(conn)
        from .api._db import resolve_run as _resolve
        run = _resolve(conn, args.run, args.project)
        if not run:
            print("no runs ingested yet", file=sys.stderr)
            return EXIT_STORE
        ruleset = load_ruleset(cfg.config_dir)

        from .analytics import inventory as inv
        candidates = inv.takeover(conn, run["id"], ruleset.takeover)["candidates"]
        if not candidates:
            print("no takeover candidates in this run — nothing to verify")
            return EXIT_OK

        scope = candidates[: args.limit] if args.limit else candidates
        print("This is the only frogscope command that sends network traffic.")
        print(f"It will resolve DNS for {len(scope)} hostname(s) from this scan"
              + (" and issue one HTTP GET to each" if not args.dns_only else "")
              + ".")
        print("It does not claim, register, or modify anything.")
        print()
        for candidate in scope:
            print(f"  {candidate['grade']:6s} {candidate['host']}")
        print()

        if not args.yes:
            try:
                answer = input("Proceed? [y/N] ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                answer = ""
            if answer not in ("y", "yes"):
                print("cancelled")
                return EXIT_OK

        def progress(done: int, total: int, host: str) -> None:
            print(f"  [{done}/{total}] {host}")

        outcome = verify_mod.verify_run(
            conn, run, ruleset, timeout=args.timeout, delay=args.delay,
            do_http=not args.dns_only, limit=args.limit, on_progress=progress)
        verify_mod.persist(conn, run["id"], outcome)
    finally:
        conn.close()

    print()
    if args.json:
        print(json.dumps(outcome, indent=2, default=str))
        return EXIT_OK

    labels = {
        "confirmed": "CONFIRMED dangling",
        "likely": "likely dangling",
        "stale_record": "stale DNS record",
        "not_dangling": "not dangling (scan false positive)",
        "unconfirmed": "unconfirmed",
    }
    rows = [{
        "verdict": labels.get(r["verdict"], r["verdict"]),
        "host": r["host"],
        "scan_grade": r["scan_grade"],
        "status": r["http_status"] if r["http_status"] is not None else "—",
        "cname_target": r["cname_target"] or "—",
    } for r in outcome["results"]]
    print(_fmt_table(rows, ["verdict", "host", "scan_grade", "status",
                            "cname_target"]))
    print()
    for result in outcome["results"]:
        if result["verdict"] in ("confirmed", "likely"):
            print(f"{result['host']}: {result['reason']}")
    print()
    print(f"checked {outcome['checked']} of {outcome['candidates_in_run']} "
          f"candidates — {outcome['by_verdict']}")
    confirmed = outcome["by_verdict"].get("confirmed", 0)
    return EXIT_THRESHOLD if (confirmed and args.fail_on_confirmed) else EXIT_OK


def cmd_watch(args) -> int:
    """Ingest any httpx output dropped into a folder."""
    import time as _time

    from .ingest import pipeline
    from .ingest.store import now_iso

    cfg = load_config(args.config, args.data)
    folder = Path(args.folder)
    if not folder.is_dir():
        print(f"not a directory: {folder}", file=sys.stderr)
        return EXIT_USAGE

    patterns = ("*.csv", "*.tsv", "*.json", "*.jsonl", "*.csv.gz")
    print(f"watching {folder} for {', '.join(patterns)}")
    print(f"polling every {args.interval}s. Ctrl-C to stop.")
    if args.once:
        print("single pass (--once)")

    conn = connect(cfg.db_path)
    try:
        migrate(conn)
        while True:
            found = sorted(
                {path for pattern in patterns for path in folder.glob(pattern)})
            for path in found:
                seen = conn.execute(
                    "SELECT sha256, outcome FROM watched_files WHERE path = ?",
                    (str(path),)).fetchone()
                digest = _file_digest(path)
                if seen and seen["sha256"] == digest:
                    continue

                # A file still being copied in would ingest as a truncated scan,
                # so wait until its size stops changing.
                if not _is_settled(path):
                    print(f"  {path.name}: still being written, will retry")
                    continue

                label = args.label or path.stem
                try:
                    result = pipeline.ingest(
                        conn, cfg, path, project=args.project,
                        project_name=args.project_name, label=label,
                        run_kind=args.kind,
                        allow_incomplete=args.allow_incomplete,
                        allow_drift=args.allow_drift)
                    outcome, message, run_id = ("ingested",
                                                f"{result.endpoint_count} endpoints",
                                                result.run_id)
                    print(f"  {path.name}: ingested as {result.run_key} "
                          f"({result.endpoint_count} endpoints, "
                          f"{result.host_count} hosts)")
                    for warning in result.warnings[:3]:
                        print(f"      ! {warning}")
                    if args.notify:
                        _notify_after_ingest(conn, cfg, result.run_id)
                except pipeline.DuplicateRun as exc:
                    outcome, message, run_id = "duplicate", str(exc), None
                    print(f"  {path.name}: already ingested, skipped")
                except pipeline.IncompleteScan as exc:
                    outcome, message, run_id = "skipped", str(exc), None
                    flag = "--" + exc.override.replace("_", "-")
                    print(f"  {path.name}: {exc} — skipped "
                          f"(pass {flag} to accept)")
                except Exception as exc:
                    outcome = "error"
                    message = f"{type(exc).__name__}: {exc}"
                    run_id = None
                    print(f"  {path.name}: {message}", file=sys.stderr)

                conn.execute(
                    "INSERT OR REPLACE INTO watched_files "
                    "(path, sha256, run_id, outcome, message, seen_at) "
                    "VALUES (?,?,?,?,?,?)",
                    (str(path), digest, run_id, outcome, message[:500], now_iso()))
                conn.commit()

            if args.once:
                break
            _time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        conn.close()
    return EXIT_OK


def _notify_after_ingest(conn, cfg, run_id: int) -> None:
    """Notify for a freshly ingested run.

    Wrapped so a broken webhook cannot kill the watcher — the ingest already
    succeeded and the data is stored, and losing the folder watcher over a
    delivery failure would be a worse outcome than a missed alert.
    """
    from .scoring.rules import load_ruleset

    try:
        run = conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
        if run is None:
            return
        _notify_run(conn, cfg, run, load_ruleset(cfg.config_dir),
                    send=True, quiet=True)
    except Exception as exc:  # noqa: BLE001 — the watcher must survive this
        print(f"      ! notification failed: {type(exc).__name__}: {exc}",
              file=sys.stderr)


def _file_digest(path: Path) -> str:
    import hashlib
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_settled(path: Path, checks: int = 2, gap: float = 1.0) -> bool:
    """True when the file size stops changing — it is not still being copied."""
    import time as _time
    last = -1
    for _ in range(checks):
        size = path.stat().st_size
        if size == last:
            return True
        last = size
        _time.sleep(gap)
    return path.stat().st_size == last
