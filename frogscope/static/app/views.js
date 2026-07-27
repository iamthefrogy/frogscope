// Views. Phase 1 ships Overview, Endpoints, Hosts, Coverage, and Runs.
// Risk scoring, findings, trends, and diff arrive in later phases, so anything
// that needs them says so rather than showing an empty box.

import { h } from 'preact';
import { useEffect, useMemo, useRef, useState } from 'preact/hooks';
import htm from 'htm';
import { SNAP, authFetch, store } from './store.js';
import { Facets } from './facets.js';
import { ColumnPicker, DataGrid } from './grid.js';
import { Drawer } from './drawer.js';
import { SEVERITY, SeverityChip } from './risk.js';
import { DangerZone, DeleteRunButton, ProjectChooser } from './manage.js';
import { CardTitle } from './help.js';
import { ScanPanel } from './scan.js';
import { SchedulePanel } from './schedule.js';
import {
  describeFilters, downloadText, num, parseOmnibox, responseClassMeta, titleCase, when,
} from './lib.js';

const html = htm.bind(h);

// ── Overview ────────────────────────────────────────────────────────────────

const KPIS = [
  { key: 'endpoints', label: 'Endpoints probed',
    note: 'Unique host and port pairs after collapsing repeat probes.' },
  { key: 'real_endpoints', label: 'Real endpoints',
    note: 'Excludes scan artefacts and Cloudflare alias ports.' },
  { key: 'hosts', label: 'Hosts' },
  { key: 'serving', label: 'Serving content',
    note: 'Returning an application response, not a block or an error.' },
  { key: 'no_waf', label: 'No WAF in front',
    note: 'Serving content with no WAF or CDN inspecting traffic.' },
  { key: 'origin_exposed', label: 'Reached directly',
    note: 'No managed proxy or platform at all.' },
  { key: 'auth_surfaces', label: 'Login surfaces' },
  { key: 'mgmt_surfaces', label: 'Management consoles' },
  { key: 'remote_access', label: 'Remote-access portals' },
  { key: 'broken_origin', label: 'Broken or missing origin',
    note: 'Cloudflare cannot reach the origin — includes takeover candidates.' },
  { key: 'nonprod_exposed', label: 'Non-production reachable' },
  { key: 'unique_ips', label: 'Distinct IPs' },
];

export function OverviewView({ run, project, onNavigate }) {
  const [data, setData] = useState(null);
  const [risk, setRisk] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    store.summary(run, project).then(setData).catch((e) => setError(e.message));
    const q = new URLSearchParams();
    if (run) q.set('run', run);
    if (project) q.set('project', project);
    authFetch(`/api/risk?${q}`).then((r) => r.json())
      .then((d) => setRisk(d.error ? null : d)).catch(() => setRisk(null));
  }, [run, project]);

  if (error) {
    return html`<div class="view-scroll"><div class="empty">
      <h2>Nothing ingested yet</h2>
      <p class="muted">${error}</p>
      <button class="btn btn-primary" onClick=${() => onNavigate('runs')}>
        Upload an httpx CSV</button>
    </div></div>`;
  }
  if (!data) return html`<div class="loading">Loading…</div>`;

  const s = data.summary || {};
  const r = data.run || {};
  const warnings = r.warnings || [];
  const total = s.endpoints || 1;

  const composition = [
    { key: 'real_endpoints', label: 'Real endpoints', value: s.real_endpoints,
      colour: 'var(--series-1)' },
    { key: 'cf_alias_ports', label: 'Cloudflare alias ports', value: s.cf_alias_ports,
      colour: 'var(--series-4)' },
    { key: 'scan_artifacts', label: 'Scan artefacts', value: s.scan_artifacts,
      colour: 'var(--color-text-subtle)' },
  ];

  return html`<div class="view-scroll">
    ${r.incomplete ? html`<div class="banner">
      <span>▲</span>
      <div><strong>This run may be incomplete.</strong>${' '}
        ${warnings.map((w) => html`<div>${w}</div>`)}
        Trend comparisons against a truncated scan read as a false improvement.
      </div>
    </div>` : null}

    ${risk ? html`<div class="card" style="margin-bottom:16px">
      <${CardTitle} topic="exec.posture">Risk posture<//>
      <div style="display:flex;gap:26px;align-items:baseline;flex-wrap:wrap">
        <div>
          <div class="kpi-value">${risk.residual_risk.index ?? '—'}<span
            class="muted" style="font-size:14px">/100</span></div>
          <div class="kpi-label">Residual risk index</div>
          <div class="kpi-note">Higher is better. Formula on the Methodology tab.</div>
        </div>
        <div>
          <div class="chip-list">
            ${Object.keys(SEVERITY)
              .filter((sev) => (risk.findings.by_severity || {})[sev])
              .map((sev) => html`
                <a href="#" onClick=${(e) => { e.preventDefault(); onNavigate('findings'); }}>
                  <${SeverityChip} severity=${sev}
                    count=${risk.findings.by_severity[sev]} /></a>`)}
          </div>
          <div class="kpi-label" style="margin-top:4px">
            ${`${num(risk.findings.total)} findings across `
              + `${num(risk.findings.affected_hosts)} hosts`}</div>
          <div class="kpi-note">Deduplicated per rule and host.</div>
        </div>
      </div>
      ${(risk.skipped_rules || []).length ? html`<div class="kpi-note"
        style="margin-top:10px">
        ${risk.skipped_rules.length} rule(s) could not be evaluated because this
        scan did not collect the data they need — they are skipped, not scored as
        passing. See Coverage for the flags that would fill them in.
      </div>` : null}
    </div>` : null}

    ${risk && (risk.top_hosts || []).length ? html`<div class="card"
      style="margin-bottom:16px">
      <h3>Highest-risk hosts</h3>
      <div class="scroll-x"><table class="plain">
        <thead><tr><th>Host</th><th>Band</th><th class="right">Score</th>
          <th class="right">Findings</th><th>Environment</th></tr></thead>
        <tbody>${risk.top_hosts.slice(0, 8).map((hst) => html`<tr>
          <td><a href="#" onClick=${(e) => { e.preventDefault();
            onNavigate('exec', { filters: { host: [hst.host] } }); }}>
            ${hst.host_display || hst.host}</a></td>
          <td><${SeverityChip} severity=${hst.risk_band} /></td>
          <td class="num right">${hst.risk_score}</td>
          <td class="num right">${hst.finding_count}</td>
          <td>${hst.env}</td>
        </tr>`)}</tbody>
      </table></div>
    </div>` : null}

    <div class="grid-cards" style="margin-bottom:16px">
      ${KPIS.filter((k) => s[k.key] !== undefined).map((k) => html`
        <div class="card kpi">
          <div class="kpi-value">${num(s[k.key])}</div>
          <div class="kpi-label">${k.label}</div>
          ${k.note && html`<div class="kpi-note">${k.note}</div>`}
        </div>`)}
    </div>

    <div class="card" style="margin-bottom:16px">
      <${CardTitle} topic="grid.artifacts">What this scan actually covered<//>
      <p class="muted" style="margin-top:0">
        Of ${num(s.endpoints)} probed endpoints, only ${num(s.real_endpoints)} are
        distinct services. The rest are Cloudflare proxy aliases of a site already
        counted, or artefacts of probing a TLS-only port over cleartext.
      </p>
      <div class="bar" style="height:14px">
        ${composition.map((seg) => seg.value > 0 && html`
          <span style=${`width:${(100 * seg.value / total).toFixed(2)}%;background:${seg.colour}`}
                title=${`${seg.label}: ${seg.value}`}></span>`)}
      </div>
      <div class="chip-list" style="margin-top:8px">
        ${composition.map((seg) => html`<span class="chip">
          <span style=${`display:inline-block;width:8px;height:8px;border-radius:2px;background:${seg.colour}`}></span>
          ${seg.label} ${num(seg.value)}
        </span>`)}
      </div>
    </div>

    <div style="display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(300px,1fr))">
      <div class="card">
        <h3>Response classes</h3>
        <${Breakdown} data=${s.by_response_class} total=${total}
          labeller=${(k) => {
            const meta = responseClassMeta(k);
            return `${meta.glyph} ${meta.label}`;
          }}
          onPick=${(k) => onNavigate('exec', { filters: { response_class: [k] } })} />
      </div>
      <div class="card">
        <h3>Hosts by environment</h3>
        <${Breakdown} data=${s.by_env} total=${s.hosts || 1}
          labeller=${(k) => titleCase(k)}
          onPick=${(k) => onNavigate('exec', { filters: { env: [k] } })} />
      </div>
    </div>

    <div class="card" style="margin-top:16px">
      <h3>Scan metadata</h3>
      <dl class="kv">
        <dt>Run</dt><dd><code>${r.run_key}</code></dd>
        <dt>Label</dt><dd>${r.label || '—'}</dd>
        <dt>Scan window</dt>
        <dd>${when(r.started_at)} → ${when(r.completed_at)}
          ${r.scan_duration_s
            ? html` <span class="muted">(${Math.round(r.scan_duration_s / 60)} min)</span>`
            : ''}</dd>
        <dt>Source rows</dt><dd>${num(r.row_count)}</dd>
        <dt>Ports probed</dt><dd>${(s.ports || []).join(', ')}</dd>
        <dt>Config version</dt><dd><code>${r.config_hash}</code></dd>
      </dl>
    </div>

    <div class="banner info" style="margin-top:16px">
      Run-over-run deltas and trend charts arrive in the next phase. Everything
      shown here describes a single scan.
    </div>
  </div>`;
}

function Breakdown({ data, total, labeller, onPick }) {
  const entries = Object.entries(data || {});
  if (!entries.length) return html`<p class="subtle">No data.</p>`;
  const max = Math.max(...entries.map(([, v]) => v));
  return html`<table class="plain"><tbody>
    ${entries.map(([key, value]) => html`<tr>
      <td style="width:45%"><a href="#" onClick=${(e) => {
        e.preventDefault(); onPick && onPick(key);
      }}>${labeller ? labeller(key) : key}</a></td>
      <td style="width:35%">
        <div class="fill-bar"><span style=${`width:${(100 * value / max).toFixed(1)}%`}></span></div>
      </td>
      <td class="num right" style="width:20%">${num(value)}
        <span class="subtle">${((100 * value) / total).toFixed(0)}%</span></td>
    </tr>`)}
  </tbody></table>`;
}

// ── Endpoints grid ──────────────────────────────────────────────────────────

export function EndpointsView({ run, project, catalog, state, onState, extraFilters,
                               onSaveColumnsDefault }) {
  const [result, setResult] = useState(null);
  const [facets, setFacets] = useState({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [drawerKey, setDrawerKey] = useState(null);
  const [showPicker, setShowPicker] = useState(false);
  // Visible by default — a collapse button hides it for more grid width,
  // rather than the filter surface being an extra click to find.
  const [showFacets, setShowFacets] = useState(true);
  const [omnibox, setOmnibox] = useState(state.search || '');
  const [saved, setSaved] = useState([]);
  const [savePrompt, setSavePrompt] = useState(false);
  const [columnsRemembered, setColumnsRemembered] = useState(false);
  const [saveName, setSaveName] = useState('');
  const gridWrapRef = useRef(null);

  const loadSaved = () => {
    const q = new URLSearchParams();
    if (project) q.set('project', project);
    authFetch(`/api/views?${q}`).then((r) => r.json())
      .then((d) => setSaved(d.views || [])).catch(() => setSaved([]));
  };
  useEffect(() => { loadSaved(); }, [project]);

  const saveCurrent = async () => {
    const name = saveName.trim();
    if (!name) return;
    const res = await authFetch('/api/views', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name, project, view: 'endpoints',
        state: { filters, search: state.search || '', sort: state.sort,
                 columns: visible },
      }),
    });
    if (res.ok) { setSavePrompt(false); setSaveName(''); loadSaved(); }
  };

  const columnsByKey = useMemo(
    () => Object.fromEntries((catalog.columns || []).map((c) => [c.key, c])), [catalog]);

  const visible = state.columns || catalog.default_visible || [];
  const filters = state.filters || {};
  const page = state.page || 1;
  const pageSize = state.pageSize || 50;

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    const body = {
      run, project,
      // `extraFilters` (e.g. a scoped tab's internal NULL-exclusion trick,
      // see `main.js`'s `CERTIFICATE_FILTERS`) is applied to the query but
      // deliberately excluded from `filters` — never shown as a chip, never
      // pre-filled in the grid's own column filter box, never saved with a
      // view. `filters` spreads LAST so a user's own filter on the same
      // field (e.g. typing a real "expires within 30 days" range on
      // `cert_days_remaining`) overrides rather than gets silently
      // discarded — any real range the user sets already excludes null/
      // no-cert rows on its own, so the scoping still holds either way.
      filters: { ...(extraFilters || {}), ...filters },
      search: state.search || '', sort: state.sort,
      page, page_size: pageSize,
      columns: visible,
      with_facets: true,
    };
    store.query(body)
      .then((res) => {
        if (cancelled) return;
        setResult(res);
        if (res.facets) setFacets(res.facets);
      })
      .catch((e) => !cancelled && setError(e.message))
      .finally(() => !cancelled && setLoading(false));
    return () => { cancelled = true; };
  }, [run, project, JSON.stringify(filters), JSON.stringify(extraFilters),
      state.search, state.sort, page, pageSize, JSON.stringify(visible)]);

  const setFilter = (key, value) => {
    const next = { ...filters };
    if (value === null || value === undefined || value === ''
        || (Array.isArray(value) && !value.length)) delete next[key];
    else next[key] = value;
    onState({ filters: next, page: 1 });
  };

  const toggleFacet = (key, value) => {
    const col = columnsByKey[key];
    const current = filters[key];
    if (col && col.is_list) {
      const values = new Set((current && current.values) || []);
      values.has(value) ? values.delete(value) : values.add(value);
      setFilter(key, values.size ? { values: [...values], mode: (current && current.mode) || 'any' } : null);
      return;
    }
    const values = new Set((Array.isArray(current) ? current : current ? [current] : []).map(String));
    const text = String(value);
    values.has(text) ? values.delete(text) : values.add(text);
    setFilter(key, values.size ? [...values] : null);
  };

  const applyOmnibox = (text) => {
    const parsed = parseOmnibox(text, columnsByKey);
    onState({ filters: parsed.filters, search: parsed.search, page: 1 });
  };

  const shownColumns = visible.map((k) => columnsByKey[k]).filter(Boolean);
  const chips = describeFilters(filters, columnsByKey);
  const emptySource = new Set(catalog.empty_source_columns || []);

  return html`<div class="view">
    <div class="toolbar">
      <input class="input omnibox" placeholder="env:prod no_waf response_class:live_content  — press Enter"
        value=${omnibox}
        onInput=${(e) => setOmnibox(e.target.value)}
        onKeyDown=${(e) => { if (e.key === 'Enter') applyOmnibox(omnibox); }} />
      <button class="btn" onClick=${() => applyOmnibox(omnibox)}>Apply</button>

      <select class="input" onChange=${(e) => {
        const [kind, id] = e.target.value.split(':');
        if (kind === 'preset') {
          const preset = (catalog.filter_presets || []).find((p) => p.id === id);
          if (preset) { onState({ filters: preset.filters, page: 1 }); setOmnibox(''); }
        } else if (kind === 'saved') {
          const view = saved.find((v) => String(v.id) === id);
          if (view) {
            onState({ ...view.state, page: 1 });
            setOmnibox(view.state.search || '');
            authFetch(`/api/views/${view.id}/used`, { method: 'POST' });
          }
        }
        e.target.value = '';
      }}>
        <option value="">Views…</option>
        ${saved.length ? html`<optgroup label="Saved">
          ${saved.map((v) => html`
            <option value=${`saved:${v.id}`}>${v.name}</option>`)}
        </optgroup>` : null}
        <optgroup label="Built in">
          ${(catalog.filter_presets || []).map((p) => html`
            <option value=${`preset:${p.id}`}>${p.label}</option>`)}
        </optgroup>
      </select>
      <button class="btn" title="Save the current filters, sort, and columns"
        onClick=${() => setSavePrompt(!savePrompt)}>Save view</button>

      <span class="spacer"></span>

      <button class="btn" title=${showFacets ? 'Hide the filter sidebar' : 'Show the filter sidebar'}
        onClick=${() => setShowFacets(!showFacets)}>
        ${showFacets ? '◂ Hide filters' : '▸ Filters'}</button>
      <button class="btn" onClick=${() => setShowPicker(true)}>
        Columns (${visible.length})</button>
      ${onSaveColumnsDefault ? html`<button class="btn" title="Remember this column
        selection on this browser, so it's what you see next time"
        onClick=${() => {
          onSaveColumnsDefault(visible);
          setColumnsRemembered(true);
          setTimeout(() => setColumnsRemembered(false), 1500);
        }}>${columnsRemembered ? '✓ Remembered' : 'Remember columns'}</button>` : null}
      <button class="btn" onClick=${() => store.download(store.exportUrl({
        run, project, filters, search: state.search, sort: state.sort, columns: visible,
      }, 'csv'), 'endpoints.csv')}>CSV</button>
      <button class="btn" title="Multi-sheet workbook of this run, honouring the filter"
        onClick=${() => store.download(workbookUrl({ run, project, filters, search: state.search,
                             sort: state.sort, columns: visible }), 'workbook.xlsx')}>Excel</button>
      <button class="btn" onClick=${() => copyHosts(result)}>Copy hosts</button>
    </div>

    ${savePrompt ? html`<div class="toolbar" style="padding-top:6px">
      <input class="input" style="min-width:240px" autofocus
        placeholder="Name this view" value=${saveName}
        onInput=${(e) => setSaveName(e.target.value)}
        onKeyDown=${(e) => { if (e.key === 'Enter') saveCurrent(); }} />
      <button class="btn btn-primary" onClick=${saveCurrent}>Save</button>
      <button class="btn" onClick=${() => setSavePrompt(false)}>Cancel</button>
      <span class="subtle" style="font-size:11px">
        Stored on the server, so it survives a different browser.</span>
      ${saved.map((v) => html`<span class="chip removable"
        title="Click to delete"
        onClick=${async () => {
          await authFetch(`/api/views/${v.id}`, { method: 'DELETE' });
          loadSaved();
        }}>${v.name} ✕</span>`)}
    </div>` : null}

    ${chips.length ? html`<div class="toolbar" style="padding-top:6px;padding-bottom:6px">
      <span class="muted" style="font-size:11px">Active:</span>
      ${chips.map((chip) => html`
        <span class="chip removable" onClick=${() => setFilter(chip.key, null)}
          title="Click to remove">${chip.text} ✕</span>`)}
      <button class="btn btn-sm" onClick=${() => {
        onState({ filters: {}, search: '', page: 1 }); setOmnibox('');
      }}>Clear all</button>
    </div>` : null}

    ${emptySource.size ? html`<div class="toolbar" style="padding-top:4px;padding-bottom:4px">
      <span class="subtle" style="font-size:11px">
        ${emptySource.size} httpx column(s) were entirely empty in this run and are
        hidden. See Coverage for the recommended flags.
      </span>
    </div>` : null}

    <div class="main">
      ${showFacets ? html`<${Facets} catalog=${catalog.columns} facets=${facets} filters=${filters}
        onToggle=${toggleFacet}
        onClear=${() => { onState({ filters: {}, search: '', page: 1 }); setOmnibox(''); }}
        onCollapse=${() => setShowFacets(false)} />`
        : html`<button class="btn btn-sm" title="Show the filter sidebar"
            onClick=${() => setShowFacets(true)}
            style="align-self:flex-start;margin-right:8px;padding:5px 7px">▸</button>`}

      <div class="view">
        ${error ? html`<div class="banner error">${error}</div>` : null}
        ${loading && !result ? html`<div class="loading">Loading…</div>` : null}
        ${result ? html`<${DataGrid}
          columns=${shownColumns} rows=${result.rows} sort=${state.sort}
          filters=${filters} facets=${facets}
          onSort=${(s) => onState({ sort: s })}
          onFilter=${setFilter}
          onRow=${(row) => setDrawerKey(row.endpoint_key)} scrollRef=${gridWrapRef} />` : null}

        ${result ? html`<div class="pager">
          <span class="muted">
            Showing ${num(result.rows.length)} of ${num(result.total)} matching
            ${loading ? ' — updating…' : ''}
          </span>
          <span class="spacer"></span>
          <select class="input" value=${String(pageSize)}
            onChange=${(e) => onState({ pageSize: Number(e.target.value), page: 1 })}>
            ${[10, 25, 50].map((n) => html`<option value=${n}>${n} / page</option>`)}
          </select>
          <button class="btn btn-sm" disabled=${page <= 1}
            onClick=${() => onState({ page: page - 1 })}>Prev</button>
          <span class="muted">${page} / ${result.pages}</span>
          <button class="btn btn-sm" disabled=${page >= result.pages}
            onClick=${() => onState({ page: page + 1 })}>Next</button>
          <span class="spacer"></span>
          <button class="btn btn-sm" title="Scroll the table left"
            onClick=${() => gridWrapRef.current
              && gridWrapRef.current.scrollBy({ left: -400, behavior: 'smooth' })}>◀</button>
          <button class="btn btn-sm" title="Scroll the table right"
            onClick=${() => gridWrapRef.current
              && gridWrapRef.current.scrollBy({ left: 400, behavior: 'smooth' })}>▶</button>
        </div>` : null}
      </div>
    </div>

    ${drawerKey ? html`<${Drawer} endpointKey=${drawerKey} run=${run} project=${project}
      onClose=${() => setDrawerKey(null)} />` : null}
    ${showPicker ? html`<${ColumnPicker} catalog=${catalog.columns} groups=${catalog.groups}
      visible=${visible} presets=${catalog.presets}
      onChange=${(cols) => onState({ columns: cols })}
      onClose=${() => setShowPicker(false)} />` : null}
  </div>`;
}

function copyHosts(result) {
  if (!result) return;
  const hosts = [...new Set(result.rows.map((r) => r.host_display || r.host))];
  navigator.clipboard.writeText(hosts.join('\n'));
}

// Restricts a full catalog down to one category's fields — Facets, the
// omnibox's field-name parsing, and the Columns picker's "add back" list all
// read from `catalog.columns`, so trimming it here is what makes a scoped
// tab's search/filter surface actually scoped, not just its default column
// set. `presets`/`filter_presets` are dropped rather than filtered: they are
// column-set/filter shortcuts built for the full "All Assets" catalog and can
// reference fields outside a category's scope.
function scopeCatalog(catalog, keys, excludeKeys) {
  const excluded = new Set(excludeKeys || []);
  // `null` means "no restriction" — the Summary leaderboard's "All" chip
  // wants the full, unscoped catalog (every column, every preset), not a
  // category subset. `excludeKeys` still applies on top of that: a handful
  // of columns (e.g. `top_finding`) can be dropped everywhere — the table,
  // the Columns picker, Facets — without narrowing the rest of the catalog.
  if (!keys) {
    if (!excluded.size) return catalog;
    return {
      ...catalog,
      columns: (catalog.columns || []).filter((c) => !excluded.has(c.key)),
      default_visible: (catalog.default_visible || []).filter((k) => !excluded.has(k)),
      empty_source_columns: (catalog.empty_source_columns || []).filter((k) => !excluded.has(k)),
    };
  }
  const allowed = new Set(keys.filter((k) => !excluded.has(k)));
  return {
    ...catalog,
    columns: (catalog.columns || []).filter((c) => allowed.has(c.key)),
    default_visible: (catalog.default_visible || []).filter((k) => allowed.has(k)),
    presets: [],
    filter_presets: [],
    empty_source_columns: (catalog.empty_source_columns || []).filter((k) => allowed.has(k)),
  };
}

// `frogscope:columns:<persistKey>` — a per-browser remembered column
// selection. Deliberately localStorage, not the server-side "Save view"
// feature just below it: that one names, stores, and shares a full
// filter+sort+column snapshot per project; this is the lighter "just
// remember which columns I like" preference, per person, that applies the
// moment the tab is opened rather than requiring a pick from the Views menu.
function loadPersistedColumns(persistKey) {
  if (!persistKey) return null;
  try {
    const raw = localStorage.getItem(`frogscope:columns:${persistKey}`);
    const parsed = raw && JSON.parse(raw);
    return Array.isArray(parsed) && parsed.length ? parsed : null;
  } catch { return null; }
}

function savePersistedColumns(persistKey, columns) {
  if (!persistKey) return;
  localStorage.setItem(`frogscope:columns:${persistKey}`, JSON.stringify(columns));
}

// `EndpointsView` with its own private state and a restricted catalog —
// "All Assets" is the master table; each of these is that same table
// pre-scoped to one category's columns, filters, and (via `defaultFilters`)
// rows. State resets to the given defaults each time the tab is mounted,
// same lifecycle every other non-`endpoints` tab already has, so switching
// tabs never leaks one category's filters/columns into another.
export function ScopedEndpointsView({ run, project, catalog, columnKeys, excludeKeys,
                                     defaultColumns, defaultFilters, hiddenFilters,
                                     defaultSort, persistKey }) {
  const scoped = useMemo(() => scopeCatalog(catalog, columnKeys, excludeKeys),
    [catalog, columnKeys, excludeKeys]);
  const [state, setState] = useState({
    columns: loadPersistedColumns(persistKey) || defaultColumns,
    filters: defaultFilters || {}, sort: defaultSort,
  });
  const onState = (patch) => setState((prev) => ({ ...prev, ...patch }));
  return html`<${EndpointsView} run=${run} project=${project} catalog=${scoped}
    state=${state} onState=${onState} extraFilters=${hiddenFilters}
    onSaveColumnsDefault=${persistKey
      ? (cols) => savePersistedColumns(persistKey, cols) : null} />`;
}

// ── Hosts ───────────────────────────────────────────────────────────────────

export function HostsView({ run, project, onNavigate }) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [search, setSearch] = useState('');

  useEffect(() => {
    store.hosts(run, project).then(setData).catch((e) => setError(e.message));
  }, [run, project]);

  if (error) return html`<div class="view-scroll"><div class="banner error">${error}</div></div>`;
  if (!data) return html`<div class="loading">Loading…</div>`;

  const needle = search.toLowerCase();
  const hosts = (data.hosts || []).filter((hst) => !needle || hst.host.includes(needle));

  return html`<div class="view">
    <div class="toolbar">
      <input class="input" style="min-width:260px" placeholder="Find a host…"
        value=${search} onInput=${(e) => setSearch(e.target.value)} />
      <span class="muted">${num(hosts.length)} hosts</span>
    </div>
    <div class="grid-wrap">
      <table class="grid">
        <thead><tr>
          <th>Host</th><th>Env</th><th>Zone</th>
          <th class="right">Ports</th><th class="right">Serving</th>
          <th class="right">Real</th><th>Provider</th><th>CDN</th>
          <th>Flags</th><th class="right">IPs</th><th class="right">Apps</th>
        </tr></thead>
        <tbody>
          ${hosts.map((hst) => html`<tr key=${hst.host}
            onClick=${() => onNavigate('exec', { filters: { host: [hst.host] } })}
            style="cursor:pointer">
            <td>${hst.host_display || hst.host}</td>
            <td>${hst.env}</td>
            <td class="subtle">${hst.zone}</td>
            <td class="cell-num">${hst.port_count}</td>
            <td class="cell-num">${hst.serving_port_count}</td>
            <td class="cell-num">${hst.real_port_count}</td>
            <td>${hst.hosting_provider || html`<span class="subtle">—</span>`}</td>
            <td>${hst.cdn_name || html`<span class="subtle">none</span>`}</td>
            <td><span class="chip-list">
              ${hst.origin_exposed
                && html`<span class="chip" data-state="bad">▲ direct</span>`}
              ${hst.cdn_bypass_candidate
                && html`<span class="chip" data-state="bad">▲ WAF bypassable</span>`}
              ${hst.no_waf_count > 0
                && html`<span class="chip" data-state="warn">▲ ${hst.no_waf_count} no WAF</span>`}
              ${hst.has_mgmt_surface
                && html`<span class="chip" data-state="bad">▲ mgmt</span>`}
              ${hst.has_auth_surface
                && html`<span class="chip" data-state="good">🔒 auth</span>`}
              ${hst.origin_health && hst.origin_health !== 'ok'
                && html`<span class="chip" data-state="bad">▲ ${hst.origin_health}</span>`}
            </span></td>
            <td class="cell-num">${hst.distinct_ip_count}</td>
            <td class="cell-num">${hst.service_diversity}</td>
          </tr>`)}
        </tbody>
      </table>
    </div>
  </div>`;
}

// ── Coverage / data quality ─────────────────────────────────────────────────

export function CoverageView({ run, project }) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    store.quality(run, project).then(setData).catch((e) => setError(e.message));
  }, [run, project]);

  if (error) return html`<div class="view-scroll"><div class="banner error">${error}</div></div>`;
  if (!data) return html`<div class="loading">Loading…</div>`;

  const columns = data.columns || [];
  const empty = data.empty_columns || [];

  return html`<div class="view-scroll">
    <div class="card" style="margin-bottom:16px">
      <h3>Why some columns are blank</h3>
      <p style="margin-top:0">
        ${empty.length} of ${columns.length} httpx columns were entirely empty in
        this run. That is a function of the flags the scan used, not missing data
        in frogscope — the columns stay defined and will populate automatically
        when a richer scan is ingested.
      </p>
      ${data.recommended_command ? html`<div>
        <div class="muted" style="font-size:11px;margin-bottom:4px">
          Suggested command for the next scan</div>
        <code style="display:block;padding:10px;background:var(--color-bg);
                     border-radius:var(--radius-sm);overflow-wrap:anywhere">
          ${data.recommended_command}</code>
        <button class="btn btn-sm" style="margin-top:8px"
          onClick=${() => navigator.clipboard.writeText(data.recommended_command)}>
          Copy</button>
      </div>` : null}
    </div>

    ${(data.suggestions || []).length ? html`<div class="card" style="margin-bottom:16px">
      <h3>What each extra flag would unlock</h3>
      <table class="plain">
        <thead><tr><th>Flag</th><th>Unlocks</th></tr></thead>
        <tbody>${data.suggestions.map((s) => html`<tr>
          <td><code>${s.flag}</code></td><td>${s.unlocks}</td>
        </tr>`)}</tbody>
      </table>
    </div>` : null}

    <div class="card" style="margin-bottom:16px">
      <h3>Duplicate probes within this scan</h3>
      <p style="margin-top:0" class="muted">
        httpx re-probed some endpoints seconds apart. Those rows are collapsed to
        one record per host and port, keeping the latest observation but taking
        the union of DNS records — the last probe alone undersamples a
        round-robin set, which would then show up as a false "IP changed" next
        run.
      </p>
      <dl class="kv">
        <dt>Endpoints with repeat probes</dt><dd>${num(data.collapsed_groups)}</dd>
        <dt>Duplicate rows removed</dt><dd>${num(data.collapsed_extra_rows)}</dd>
        <dt>Probes that disagreed</dt><dd>${num(data.inconsistent_endpoints)}</dd>
      </dl>
    </div>

    <div class="card">
      <h3>Fill rate by source column</h3>
      <div class="scroll-x"><table class="plain">
        <thead><tr><th>Column</th><th>Fill</th><th class="right">Non-empty</th>
          <th>Example value</th></tr></thead>
        <tbody>
          ${columns.map((c) => html`<tr>
            <td><code>${c.column_name}</code></td>
            <td style="min-width:120px">
              <div class="fill-bar"><span style=${`width:${c.fill_pct}%`}></span></div>
            </td>
            <td class="num right">${num(c.non_empty)}
              <span class="subtle">${c.fill_pct}%</span></td>
            <td class="subtle" style="max-width:340px;overflow:hidden;
                       text-overflow:ellipsis;white-space:nowrap">
              ${c.sample || '—'}</td>
          </tr>`)}
        </tbody>
      </table></div>
    </div>
  </div>`;
}

// ── Runs and upload ─────────────────────────────────────────────────────────

export function RunsView({ projects, project, onSelect, onProjectsChanged,
                           onIngested }) {
  const [runs, setRuns] = useState(null);

  const refresh = () => store.runs(project || undefined)
    .then(setRuns).catch(() => setRuns([]));
  useEffect(() => { refresh(); }, [project]);

  const changed = () => { refresh(); onProjectsChanged && onProjectsChanged(); };

  return html`<div class="view-scroll">
    ${SNAP
      // Read-only export: `fetch` is shimmed, so a project chooser and a
      // dropzone would look live and silently do nothing. Same reason the
      // delete controls are hidden.
      ? html`<div class="card" style="margin-bottom:16px">
          <h3>Offline export</h3>
          <p class="subtle" style="margin:0">
            This is a snapshot of one scan. Adding scans, creating projects, and
            deleting data need the live application.
          </p>
        </div>`
      : html`<div>
        <div class="card" style="margin-bottom:16px">
          <${CardTitle} topic="runs.projects">Project<//>
          <p class="subtle" style="margin:0 0 10px">
            Scans are compared within a project, never across them. A scan run
            below goes into whichever project is selected here.
          </p>
          <${ProjectChooser} projects=${projects} value=${project}
            onSelect=${onSelect}
            onCreated=${(made) => {
              onProjectsChanged && onProjectsChanged();
              onSelect && onSelect(made.slug);
            }}
            onDeleted=${() => { refresh(); onProjectsChanged && onProjectsChanged(); }} />
        </div>

        <${ScanPanel} project=${project} onIngested=${() => {
          refresh(); onIngested && onIngested();
        }} />

        <${SchedulePanel} project=${project} />
      </div>`}

    <div class="card">
      <h3>Scans in this project</h3>
      ${!runs ? html`<div class="loading">Loading…</div>` : null}
      ${runs && !runs.length
        ? html`<p class="subtle">Nothing ingested into this project yet.</p>`
        : null}
      ${runs && runs.length ? html`<div class="scroll-x"><table class="plain">
        <thead><tr><th>Run</th><th>Label</th><th>Kind</th><th>Scan window</th>
          <th class="right">Rows</th><th class="right">Endpoints</th>
          <th class="right">Hosts</th><th>Flags</th><th></th></tr></thead>
        <tbody>${runs.map((r) => html`<tr>
          <td><code>${r.run_key}</code></td>
          <td>${r.label || '—'}</td>
          <td>${r.run_kind}</td>
          <td class="subtle nowrap">${when(r.started_at)}</td>
          <td class="num right">${num(r.row_count)}</td>
          <td class="num right">${num(r.endpoint_count)}</td>
          <td class="num right">${num(r.host_count)}</td>
          <td><span class="chip-list">
            ${Boolean(r.is_baseline) && html`<span class="chip" data-state="info">baseline</span>`}
            ${Boolean(r.incomplete) && html`<span class="chip" data-state="warn">▲ incomplete</span>`}
            ${Boolean(r.duplicate_of) && html`<span class="chip" data-state="neutral">duplicate</span>`}
          </span></td>
          <td class="right"><${DeleteRunButton} run=${r} onDeleted=${changed} /></td>
        </tr>`)}</tbody>
      </table></div>` : null}
      ${runs && runs.length > 1 ? html`<p class="subtle" style="margin:10px 0 0">
        Deleting a scan leaves the stored diffs on later scans as they were, rather
        than silently rewriting history you have already read. Run${' '}
        <code>frogscope reindex</code> to rebuild them.
      </p>` : null}
    </div>

    <${DangerZone} onChanged=${changed} />
  </div>`;
}


/** Workbook export URL, carrying the active filter so the file matches the view. */
function workbookUrl({ run, project, filters, search, sort, columns }) {
  const params = new URLSearchParams();
  if (run) params.set('run', run);
  if (project) params.set('project', project);
  if (search) params.set('q', search);
  if (sort) params.set('sort', sort);
  if (filters && Object.keys(filters).length) {
    params.set('filters', JSON.stringify(filters));
  }
  if (columns) params.set('columns', columns.join(','));
  return `/api/export/workbook?${params}`;
}
