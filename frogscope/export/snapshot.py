"""Offline single-file HTML export.

Produces one .html that opens by double-click with networking disabled: no CDN,
no fonts, no API. Adapted from frogy_web/export/snapshot.py, whose base64
`data:` URL plus import-map trick is the neat part — vendored ES modules become
`data:text/javascript` URLs that a `file://` page can import.

Two departures:

* **A fetch shim rather than snapshot branches in every view.** The app makes 17
  direct `fetch` calls across 26 API paths. Adding an "if snapshot" branch to
  each would be invasive and would rot the moment a new view is added. Instead
  `window.fetch` is replaced before the app module loads, and serves the inlined
  payload. View code is untouched and cannot drift out of sync.

* **Columnar, dictionary-encoded endpoint rows.** As plain objects they are
  2.4 MB for a modest estate — most columns are low-cardinality enums repeated
  once per row. Encoded they are 387 KB, and the shim decodes them back into the
  exact shape the API returns.
"""

from __future__ import annotations

import base64
import json
import re
import sqlite3
from pathlib import Path
from typing import Any

STATIC = Path(__file__).resolve().parent.parent / "static"
TEMPLATES = Path(__file__).resolve().parent.parent / "templates"

# Dictionary-encode a column when repetition makes it worth the indirection.
_DICT_MAX_RATIO = 0.4
_DICT_MAX_ENTRIES = 3000


def _data_url(text: str, mime: str = "text/javascript") -> str:
    encoded = base64.b64encode(text.encode("utf-8")).decode("ascii")
    return f"data:{mime};base64,{encoded}"


def encode_table(rows: list[dict]) -> dict[str, Any]:
    """Columnar layout with a dictionary per low-cardinality column.

    Returns {"n", "columns", "dicts"}. A column in `dicts` stores integer
    indices; everything else stores values directly.
    """
    if not rows:
        return {"n": 0, "columns": {}, "dicts": {}}

    names = sorted({key for row in rows for key in row})
    columns: dict[str, list] = {}
    dicts: dict[str, list] = {}

    for name in names:
        values = [row.get(name) for row in rows]
        keys = [json.dumps(v, sort_keys=True, default=str) for v in values]
        unique = sorted(set(keys))
        if len(unique) <= len(values) * _DICT_MAX_RATIO \
                and len(unique) < _DICT_MAX_ENTRIES:
            index = {key: position for position, key in enumerate(unique)}
            dicts[name] = [json.loads(key) for key in unique]
            columns[name] = [index[key] for key in keys]
        else:
            columns[name] = values

    return {"n": len(rows), "columns": columns, "dicts": dicts}


# ── Payload assembly ────────────────────────────────────────────────────────

def build_payload(conn: sqlite3.Connection, cfg, run: sqlite3.Row,
                  ruleset, *, redactor=None) -> dict[str, Any]:
    """Everything the offline page needs, keyed by the API path it replaces."""
    from ..analytics import inventory as inv
    from ..analytics import kpis, narrative
    from ..ingest import timeseries
    from ..query import facets
    from ..query.catalog import Catalog

    catalog = Catalog(cfg)
    run_id, project_id = run["id"], run["project_id"]

    def rows(sql: str, params: tuple = ()) -> list[dict]:
        return [dict(r) for r in conn.execute(sql, params)]

    def parse(record: dict, *fields: str) -> dict:
        for field in fields:
            raw = record.pop(field, None)
            if raw:
                try:
                    record[field.removesuffix("_json")] = json.loads(raw)
                except (json.JSONDecodeError, TypeError):
                    pass
        return record

    run_dict = parse(dict(run), "summary_json", "warnings_json",
                     "risk_summary_json", "diff_json")

    # ── Endpoints, columnar ─────────────────────────────────────────────────
    [k for k in catalog.order if not catalog.columns[k].is_list]
    grid = facets.query_endpoints(conn, run_id, catalog,
                                  columns=catalog.order, full=True)
    endpoint_rows = grid["rows"]

    # Per-endpoint drawer detail. Only what the columnar table above does NOT
    # already carry — duplicating every scalar column here cost 5.9 MB, over a
    # third of the file, for data the grid already holds. The shim merges the two.
    # One shared pool of interned values, used by everything below. Almost all
    # the bulk in a snapshot is repetition: a Cloudflare host's thirteen alias
    # ports carry byte-identical DNS and technology arrays, and one scoring rule
    # emits the same `why` and `remediation` text on hundreds of endpoints.
    # Uncompressed, those duplicates were 11 MB of a 16 MB file.
    pool: list[Any] = []
    pool_index: dict[str, int] = {}

    def intern(value: Any) -> int:
        key = json.dumps(value, sort_keys=True, default=str)
        if key not in pool_index:
            pool_index[key] = len(pool)
            pool.append(value)
        return pool_index[key]

    columnar_keys = set(catalog.order)
    details: dict[str, dict] = {}
    for row in conn.execute(
        "SELECT * FROM endpoints WHERE run_id = ?", (run_id,)
    ):
        record = dict(row)
        # The raw source blob would roughly triple the file for something few
        # readers open, and the live app is there when someone needs it.
        record.pop("raw_json", None)
        parse(record, "lists_json", "extra_json", "inconsistent_fields")
        trimmed = {
            key: value for key, value in record.items()
            if key not in columnar_keys and value not in (None, "", [], {})
        }
        # `lists` holds the DNS and technology arrays, which are what repeat.
        if "lists" in trimmed:
            trimmed["lists"] = intern(trimmed["lists"])
        details[record["endpoint_key"]] = trimmed

    scores: dict[str, dict] = {}
    for row in conn.execute(
        "SELECT * FROM asset_scores WHERE run_id = ?", (run_id,)
    ):
        record = parse(dict(row), "contributions_json", "modifiers_json",
                       "skipped_json")
        for field in ("contributions", "modifiers", "skipped"):
            record[field] = [intern(entry) for entry in record.get(field) or []]
        scores[record["endpoint_key"]] = record

    # ── Findings ────────────────────────────────────────────────────────────
    # Only the grouped form is stored. The flat array is the same records again
    # and was over a megabyte on its own; the shim rebuilds it.
    findings = []
    for row in conn.execute(
        "SELECT * FROM findings WHERE project_id = ?", (project_id,)
    ):
        findings.append(parse(dict(row), "detail_json"))

    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: (severity_rank.get(f["severity"], 9),
                                 -(f.get("detail", {}).get("max_score") or 0)))

    rule_index = {r.id: r.as_dict() for r in ruleset.rules}
    grouped: dict[str, dict] = {}
    for finding in findings:
        group = grouped.setdefault(finding["rule_id"], {
            "rule_id": finding["rule_id"],
            "rule": rule_index.get(finding["rule_id"]),
            "severity": finding["severity"],
            "confidence": finding["confidence"],
            "title": finding["title"],
            "findings": [], "host_count": 0, "endpoint_count": 0, "max_score": 0,
        })
        group["findings"].append(finding)
        group["host_count"] += 1
        group["endpoint_count"] += (finding.get("detail") or {}).get(
            "endpoint_count", 0)
        group["max_score"] = max(group["max_score"],
                                 (finding.get("detail") or {}).get("max_score") or 0)

    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding["severity"]] = counts.get(finding["severity"], 0) + 1

    # ── Changes and history ─────────────────────────────────────────────────
    changes = [
        parse(dict(r), "before_json", "after_json", "added_json", "removed_json")
        for r in conn.execute(
            "SELECT * FROM changes WHERE run_id = ? AND is_noisy = 0", (run_id,))
    ]
    grouped_changes: dict[str, dict] = {}
    for change in changes:
        entry = grouped_changes.setdefault(change["asset_key"], {
            "asset_key": change["asset_key"], "host": change["host"],
            "change_type": change["change_type"], "fields": [],
            "worst_severity": "info", "direction": "lateral",
            "classification_only": True,
        })
        if change["field"]:
            entry["fields"].append(change)
        if not change["is_classification"]:
            entry["classification_only"] = False
            if severity_rank.get(change["severity"], 9) < \
                    severity_rank.get(entry["worst_severity"], 9):
                entry["worst_severity"] = change["severity"]
            if change["direction"] == "worse":
                entry["direction"] = "worse"
            elif change["direction"] == "better" and entry["direction"] != "worse":
                entry["direction"] = "better"

    exec_payload = kpis.build(conn, run, ruleset)
    exec_payload["narrative"] = narrative.build(exec_payload)

    labels = {m["key"]: m.get("label", m["key"])
              for m in (cfg.diff.get("metrics") or [])}
    headline = ["hosts", "real_endpoints", "hosts_needing_attention",
                "posture_index_host", "posture_index_endpoint", "findings_total",
                "findings_critical", "findings_high", "no_waf_hosts",
                "origin_exposed_hosts", "remote_access", "mgmt_surfaces",
                "eol_hosts", "takeover_candidates", "nonprod_exposed",
                "changes_added", "changes_removed", "changes_modified"]
    metrics = {}
    for name in headline:
        points = timeseries.series(conn, project_id, name, "all", 24)
        if points:
            metrics[name] = {"label": labels.get(name, name.replace("_", " ")),
                             "points": points}

    all_runs = rows(
        "SELECT id, run_key, label, run_kind, started_at, completed_at, "
        "incomplete, rules_hash, endpoint_count, host_count, row_count, "
        "is_baseline, duplicate_of FROM runs WHERE project_id = ? "
        "AND duplicate_of IS NULL ORDER BY COALESCE(started_at,''), id",
        (project_id,))

    census = rows("SELECT column_name, non_empty, total, fill_pct, sample "
                  "FROM run_columns WHERE run_id = ? ORDER BY fill_pct DESC",
                  (run_id,))

    from ..ingest import quality
    collapsed = conn.execute(
        "SELECT COUNT(*) AS n, COALESCE(SUM(probe_count - 1), 0) AS extra "
        "FROM endpoints WHERE run_id = ? AND probe_count > 1", (run_id,)
    ).fetchone()

    host_rows = []
    for row in conn.execute(
        "SELECT * FROM host_rollup WHERE run_id = ? ORDER BY host", (run_id,)
    ):
        host_rows.append(parse(dict(row), "ports_json", "ip_json", "cname_json",
                               "tech_json"))

    presence = {
        r["asset_key"]: dict(r) for r in conn.execute(
            "SELECT * FROM asset_presence WHERE project_id = ? "
            "AND asset_kind = 'endpoint'", (project_id,))
    }
    history: dict[str, list] = {}
    for row in conn.execute(
        """SELECT h.asset_key, h.field, h.run_id, h.value_json, h.changed_at,
                  r.run_key, r.label, r.started_at
             FROM asset_attr_history h JOIN runs r ON r.id = h.run_id
            WHERE h.project_id = ? ORDER BY COALESCE(r.started_at,'')""",
        (project_id,)
    ):
        record = parse(dict(row), "value_json")
        history.setdefault(record.pop("asset_key"), []).append(record)

    # One entry per endpoint per run. The run metadata repeats on every row, so
    # it is interned like everything else.
    score_history: dict[str, list] = {}
    for row in conn.execute(
        """SELECT s.endpoint_key, s.run_id, s.score, s.band, r.run_key, r.label,
                  r.started_at
             FROM asset_scores s JOIN runs r ON r.id = s.run_id
            WHERE r.project_id = ? ORDER BY COALESCE(r.started_at,'')""",
        (project_id,)
    ):
        record = dict(row)
        score_history.setdefault(record.pop("endpoint_key"), []).append(
            intern(record))

    payload: dict[str, Any] = {
        "generated_at": run_dict.get("ingested_at"),
        "offline": True,
        "run": run_dict,
        # Full list for Trends. The run picker is served only the exported run
        # by the shim, because selecting another would show this run's numbers
        # under that run's name.
        "runs": all_runs,
        "projects": rows(
            "SELECT p.*, (SELECT COUNT(*) FROM runs r WHERE r.project_id = p.id) "
            "AS run_count FROM projects p WHERE p.id = ?", (project_id,)),
        "columns": {**catalog.as_dict(),
                    "source_fill": {c["column_name"]: c["fill_pct"] for c in census},
                    "empty_source_columns": sorted(
                        c["column_name"] for c in census if c["fill_pct"] == 0.0)},
        "endpoints": encode_table(endpoint_rows),
        "endpoint_detail": details,
        "scores": scores,
        "score_pool": pool,
        "facets": grid.get("facets") or facets.compute(conn, run_id, catalog),
        "hosts": host_rows,
        "findings": {
            "grouped": sorted(grouped.values(),
                              key=lambda g: (severity_rank.get(g["severity"], 9),
                                             -g["host_count"])),
            "total": len(findings),
            "by_severity": {k: counts[k] for k in
                            ("critical", "high", "medium", "low", "info")
                            if k in counts},
            "open": sum(1 for f in findings if f["status"] == "open"),
            "resolved": sum(1 for f in findings if f["status"] == "resolved"),
            "acknowledged": sum(1 for f in findings if f["status"] == "ack"),
        },
        "rules": ruleset.as_dict(),
        "risk": {
            "run": run_dict,
            "residual_risk": (run_dict.get("risk_summary") or {}).get(
                "residual_risk", {}),
            "by_band": {
                r["band"]: r["n"] for r in conn.execute(
                    "SELECT band, COUNT(*) n FROM asset_scores WHERE run_id = ? "
                    "AND excluded = 0 GROUP BY 1", (run_id,))},
            "findings": {
                "total": len(findings),
                "by_severity": {k: counts[k] for k in
                                ("critical", "high", "medium", "low", "info")
                                if k in counts},
                "affected_hosts": len({f["asset_key"] for f in findings}),
            },
            "skipped_rules": (run_dict.get("risk_summary") or {}).get(
                "skipped_rules", []),
            "top_hosts": exec_payload["top_hosts"],
            "bands": ruleset.bands,
            "buckets": ruleset.buckets,
        },
        "exec": exec_payload,
        "summary": {"run": run_dict,
                    "summary": run_dict.get("summary", {})},
        "quality": {
            "run": run_dict, "columns": census,
            "empty_columns": [c["column_name"] for c in census
                              if c["fill_pct"] == 0.0],
            "collapsed_groups": collapsed["n"],
            "collapsed_extra_rows": collapsed["extra"],
            "inconsistent_endpoints": conn.execute(
                "SELECT COUNT(*) n FROM endpoints WHERE run_id = ? "
                "AND intra_run_inconsistent = 1", (run_id,)).fetchone()["n"],
            "suggestions": quality.suggest_httpx_flags(census),
            "recommended_command": quality.recommended_command(census),
        },
        "changes": {
            "run": run_dict,
            "previous_run": next(
                (r for r in all_runs if r["id"] == run_dict.get("prev_run_id")),
                None),
            "summary": run_dict.get("diff", {}),
            "assets": list(grouped_changes.values()),
            "total_changes": len(changes),
            "flapping": [v for v in presence.values() if v["is_flapping"]][:100],
            "rules_changed": False,
        },
        "trends": {
            # Full list for Trends. The run picker is served only the exported run
        # by the shim, because selecting another would show this run's numbers
        # under that run's name.
        "runs": all_runs, "metrics": metrics,
            "enough_runs": len(all_runs) >= 2, "available": [],
        },
        "inventory": {
            "technology": inv.technology(conn, run_id, ruleset.lifecycle),
            "infrastructure": inv.infrastructure(conn, run_id, ip_limit=200),
            "auth": inv.auth_surfaces(conn, run_id),
            "takeover": inv.takeover(conn, run_id, ruleset.takeover),
        },
        "ownership": {
            "configured": cfg.has_ownership,
            "note": cfg.ownership_note,
            "tiers": cfg.ownership.get("tiers") or {},
            "by_unit": [],
        },
        "presence": presence,
        "history": history,
        "score_history": score_history,
        "views": {"views": [], "builtin": catalog.filter_presets},
    }

    for kind, data in payload["inventory"].items():
        data["run"] = run_dict
        data["kind"] = kind
    payload["inventory"]["infrastructure"]["ownership_configured"] = cfg.has_ownership
    payload["inventory"]["infrastructure"]["ownership_note"] = cfg.ownership_note

    if redactor is not None:
        payload = _redact_payload(payload, redactor)

    return payload


def _redact_payload(payload: Any, redactor) -> Any:
    """Walk the whole payload, redacting identifiers wherever they appear.

    Register every host first, then rewrite: `text()` can only replace names it
    has already seen, and hostnames appear inside composite strings all over the
    payload (endpoint keys, URLs, titles, summaries).
    """
    def register(node: Any) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key in ("host", "host_display", "asset_key", "final_host",
                           "cname_final", "worst_endpoint") and isinstance(value, str):
                    redactor.host(value)
                elif key in ("host_ip", "ip") and isinstance(value, str):
                    redactor.ip(value)
                elif key == "registrable_domain" and isinstance(value, str):
                    redactor.domain(value)
                else:
                    register(value)
        elif isinstance(node, list):
            for item in node:
                register(item)

    register(payload)
    return redactor.text(payload)


# ── HTML assembly ───────────────────────────────────────────────────────────

_SHIM = r"""
// Offline shim. Installed BEFORE the app module so every fetch it makes is
// served from the inlined payload rather than a network that is not there.
//
// A shim rather than a snapshot branch per call site: the app makes 17 direct
// fetch calls across 26 paths, and per-call branches would rot the moment a new
// view was added.
(function () {
  const P = window.__FROGSCOPE__;

  // Undo the columnar + dictionary encoding, back into the row objects the API
  // returns, so no view code can tell the difference.
  function decode(table) {
    const out = [];
    const names = Object.keys(table.columns || {});
    for (let i = 0; i < table.n; i += 1) {
      const row = {};
      for (const name of names) {
        const raw = table.columns[name][i];
        row[name] = table.dicts[name] ? table.dicts[name][raw] : raw;
      }
      out.push(row);
    }
    return out;
  }

  const ROWS = decode(P.endpoints);
  const BY_KEY = new Map(ROWS.map((r) => [r.endpoint_key, r]));

  // The drawer detail stores only what the columnar table lacks, so put the two
  // halves back together before handing a record to a view.
  function detailFor(key) {
    const extra = P.endpoint_detail[key];
    if (!extra) return null;
    const merged = { ...(BY_KEY.get(key) || {}), ...extra };
    if (typeof merged.lists === 'number') merged.lists = P.score_pool[merged.lists];
    return merged;
  }

  // Scoring traces share one pool of interned entries.
  function scoreFor(key) {
    const record = P.scores[key];
    if (!record) return null;
    const resolve = (list) => (list || []).map((i) => P.score_pool[i]);
    return {
      ...record,
      contributions: resolve(record.contributions),
      modifiers: resolve(record.modifiers),
      skipped: resolve(record.skipped),
      buckets_meta: P.rules.buckets,
      bands: P.rules.bands,
    };
  }
  P.findingsFlat = (P.findings.grouped || []).flatMap((g) => g.findings || []);

  function matchOne(value, spec) {
    const text = String(spec);
    if (text.startsWith('!')) return String(value ?? '') !== text.slice(1);
    if (text.startsWith('~')) {
      return String(value ?? '').toLowerCase().includes(text.slice(1).toLowerCase());
    }
    if (text === 'true') return value === true || value === 1;
    if (text === 'false') return value === false || value === 0;
    if (Array.isArray(value)) {
      return value.some((v) => String(v).toLowerCase() === text.toLowerCase());
    }
    return String(value ?? '') === text;
  }

  function matches(value, spec) {
    if (Array.isArray(spec)) return !spec.length || spec.some((s) => matchOne(value, s));
    if (spec && typeof spec === 'object') {
      if ('values' in spec) {
        const list = Array.isArray(value) ? value : [value];
        const want = spec.values || [];
        if (!want.length) return true;
        const has = (t) => list.some(
          (v) => String(v).toLowerCase() === String(t).toLowerCase());
        if (spec.mode === 'all') return want.every(has);
        if (spec.mode === 'none') return !want.some(has);
        return want.some(has);
      }
      const n = Number(value);
      if (spec.min !== undefined && spec.min !== '' && n < Number(spec.min)) return false;
      if (spec.max !== undefined && spec.max !== '' && n > Number(spec.max)) return false;
      return true;
    }
    return matchOne(value, spec);
  }

  function query(body) {
    let rows = ROWS.slice();
    for (const [key, spec] of Object.entries(body.filters || {})) {
      if (spec === undefined || spec === null || spec === '') continue;
      rows = rows.filter((r) => matches(r[key], spec));
    }
    if (body.search) {
      const needle = String(body.search).toLowerCase();
      rows = rows.filter((r) => Object.values(r).some(
        (v) => String(v ?? '').toLowerCase().includes(needle)));
    }
    if (body.sort) {
      const desc = String(body.sort).startsWith('-');
      const key = String(body.sort).replace(/^[-+]/, '');
      rows.sort((a, b) => {
        const x = a[key]; const y = b[key];
        if (x === y) return 0;
        if (x === null || x === undefined) return 1;
        if (y === null || y === undefined) return -1;
        const c = typeof x === 'number' ? x - y : String(x).localeCompare(String(y));
        return desc ? -c : c;
      });
    }
    const size = Number(body.page_size || 100);
    const page = Number(body.page || 1);
    const start = (page - 1) * size;
    return {
      rows: rows.slice(start, start + size),
      total: rows.length, page, page_size: size,
      pages: Math.max(1, Math.ceil(rows.length / size)),
      run: P.run, facets: P.facets,
    };
  }

  function route(path, body) {
    const [clean] = path.split('?');
    const parts = clean.replace(/^\/api\//, '').split('/').map(decodeURIComponent);

    switch (parts[0]) {
      case 'columns':   return P.columns;
      case 'projects':  return { projects: P.projects };
      case 'runs':      return { runs: [P.run] };
      case 'summary':   return P.summary;
      case 'quality':   return P.quality;
      case 'exec':      return P.exec;
      case 'risk':      return P.risk;
      case 'rules':     return P.rules;
      case 'hosts':     return { hosts: P.hosts, run: P.run };
      case 'trends':    return P.trends;
      case 'changes':   return P.changes;
      case 'ownership': return P.ownership;
      case 'views':     return P.views;
      case 'inventory': return P.inventory[parts[1]] || { error: 'not in this export' };
      case 'findings':  return { ...P.findings, findings: P.findingsFlat };
      case 'score':     return scoreFor(parts.slice(1).join('/'))
                               || { error: 'no score for this endpoint' };
      case 'history': {
        const key = parts.slice(1).join('/');
        return {
          endpoint_key: key,
          changes: P.history[key] || [],
          presence: P.presence[key] || null,
          scores: (P.score_history[key] || []).map((i) => P.score_pool[i]),
        };
      }
      case 'diff':
        return { from: null, to: P.run,
                 summary: (P.changes.summary || { baseline: true }) };
      case 'endpoints': {
        if (parts[1] === 'query') return query(body || {});
        if (parts[1] === 'facets') return { facets: P.facets };
        const key = parts.slice(1).join('/');
        const ep = detailFor(key);
        if (!ep) return { error: 'endpoint not found: ' + key };
        return {
          endpoint: ep, run: P.run,
          same_host: ROWS.filter(
            (r) => r.host === ep.host && r.endpoint_key !== key),
          same_ip: [],
        };
      }
      default:
        return { error: 'This is an offline export. ' + clean
                        + ' needs the live application.' };
    }
  }

  const OFFLINE_WRITE = {
    error: 'This is a read-only offline export. Uploading, saving views, and '
         + 'changing finding status need the live application.',
  };

  window.fetch = function (input, init) {
    const path = typeof input === 'string' ? input : (input && input.url) || '';
    if (!path.startsWith('/api/')) {
      return Promise.resolve(new Response('', { status: 404 }));
    }
    const method = ((init && init.method) || 'GET').toUpperCase();
    let body = null;
    if (init && init.body) {
      try { body = JSON.parse(init.body); } catch (e) { body = null; }
    }
    const payload = method === 'GET' ? route(path, body) : OFFLINE_WRITE;
    const ok = !(payload && payload.error);
    return Promise.resolve({
      ok, status: ok ? 200 : 400,
      json: () => Promise.resolve(payload),
      text: () => Promise.resolve(JSON.stringify(payload)),
    });
  };
})();
"""

_BANNER = """
<div id="offline-banner" style="background:var(--color-surface-muted);
  border-bottom:1px solid var(--color-border);padding:6px 16px;font-size:12px;
  color:var(--color-text-muted)">
  Offline export &mdash; a snapshot of <strong>{label}</strong>, generated
  {generated}. Uploading, saving views, and acknowledging findings need the live
  application.{redaction}
</div>
"""


def build_html(conn: sqlite3.Connection, cfg, run: sqlite3.Row, ruleset, *,
               redactor=None) -> str:
    payload = build_payload(conn, cfg, run, ruleset, redactor=redactor)

    vendor = {
        name: (STATIC / "vendor" / f"{name}.module.js").read_text(encoding="utf-8")
        for name in ("preact", "hooks", "htm")
    }
    # hooks imports the bare specifier "preact"; rewrite it to the data URL the
    # import map will not see, since a data: module has no base to resolve from.
    preact_url = _data_url(vendor["preact"])
    vendor["hooks"] = vendor["hooks"].replace('"preact"', f'"{preact_url}"')

    # Each app module becomes a data: URL, referenced through an import map
    # under a bare specifier.
    #
    # Two approaches were wrong before this one. Concatenating everything into a
    # single module fails immediately: every view file declares
    # `const html = htm.bind(h)`, so one scope is a redeclaration error. Rewriting
    # relative imports to point directly at dependency data: URLs works, but the
    # URL of a module contains the full text of everything it imports — so a
    # shared module is duplicated once per importer, and the file grew from
    # 5 MB to 9 MB. An import map means each module's text appears exactly once
    # and the browser dedupes by specifier.
    htm_url = _data_url(vendor["htm"])
    hooks_url = _data_url(vendor["hooks"])

    imports = {
        "preact": preact_url,
        "preact/hooks": hooks_url,
        "htm": htm_url,
    }
    # `manage` is included because `views` and `main` import it, not because the
    # export can upload or delete anything — its components return null when a
    # snapshot payload is present, since `fetch` is shimmed and a live-looking
    # delete button would silently do nothing.
    modules = ("lib", "charts", "store", "risk", "facets", "grid", "history",
               "drawer", "inventory", "help", "scan", "manage", "exec", "views",
               "main")
    for name in modules:
        source = (STATIC / "app" / f"{name}.js").read_text(encoding="utf-8")
        # Relative paths cannot resolve from a data: URL, so every local import
        # becomes a bare specifier the import map knows about.
        source = re.sub(r"from '\./([a-z]+)\.js'", r"from 'frogscope/\1'", source)
        imports[f"frogscope/{name}"] = _data_url(source)

    # Escaped outside the f-string: a backslash in an f-string expression is a syntax
    # error before Python 3.12, and this package supports 3.11.
    payload_json = json.dumps(
        payload, default=str, separators=(",", ":")).replace("</", "<\\/")

    entry = imports["frogscope/main"]
    import_map = json.dumps({"imports": imports})

    css = "\n".join(
        (STATIC / "css" / name).read_text(encoding="utf-8")
        for name in ("tokens.css", "app.css", "print.css")
    )

    label = run["label"] or run["run_key"]
    banner = _BANNER.format(
        label=label,
        generated=payload.get("generated_at") or "",
        redaction=(" Hostnames and addresses are pseudonyms."
                   if redactor is not None else ""),
    )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Frogscope — {label}</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'%3E%3Ccircle cx='8' cy='8' r='6' fill='none' stroke='%2306b6d4' stroke-width='2'/%3E%3Ccircle cx='8' cy='8' r='2' fill='%2306b6d4'/%3E%3C/svg%3E">
<style>{css}</style>
<script type="importmap">{import_map}</script>
</head>
<body data-theme="dark">
{banner}
<div id="root"><div class="loading">Loading…</div></div>
<script id="frogscope-payload" type="application/json">{payload_json}</script>
<script>
window.__FROGSCOPE__ = JSON.parse(
  document.getElementById('frogscope-payload').textContent);
{_SHIM}
</script>
<script type="module" src="{entry}"></script>
</body>
</html>
"""


def write(path: Path, conn: sqlite3.Connection, cfg, run: sqlite3.Row, ruleset,
          *, redactor=None) -> int:
    html = build_html(conn, cfg, run, ruleset, redactor=redactor)
    Path(path).write_text(html, encoding="utf-8")
    return len(html.encode("utf-8"))
