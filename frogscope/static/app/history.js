// Changes and Trends views.
//
// The design problem here is not showing differences — it is refusing to show
// the ones that mean nothing. Noisy changes (a rotated IP, a fresh OAuth nonce)
// are recorded but hidden behind a toggle, and flapping assets get their own
// section so they cannot dominate the "new assets" count every week.

import { h } from 'preact';
import { useEffect, useState } from 'preact/hooks';
import htm from 'htm';
import { Sparkline, seriesColour } from './charts.js';
import { num, titleCase, when } from './lib.js';
import { SeverityChip } from './risk.js';
import { CardTitle } from './help.js';
import { authFetch } from './store.js';

const html = htm.bind(h);

const TYPE_META = {
  added:    { label: 'New',      glyph: '+', token: 'var(--series-1)' },
  returned: { label: 'Returned', glyph: '↺', token: 'var(--series-4)' },
  removed:  { label: 'Gone',     glyph: '−', token: 'var(--color-text-subtle)' },
  modified: { label: 'Changed',  glyph: '~', token: 'var(--series-2)' },
};

const DIRECTION_META = {
  worse:   { label: 'worse',   token: 'var(--status-critical)', glyph: '▲' },
  better:  { label: 'better',  token: 'var(--status-good)',     glyph: '▼' },
  lateral: { label: 'lateral', token: 'var(--color-text-muted)', glyph: '·' },
};

function DirectionChip({ direction }) {
  const meta = DIRECTION_META[direction] || DIRECTION_META.lateral;
  return html`<span class="chip" style=${`color:${meta.token};border-color:${meta.token}`}>
    ${meta.glyph} ${meta.label}</span>`;
}

// ── Changes ─────────────────────────────────────────────────────────────────

export function ChangesView({ run, project, onNavigate }) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [types, setTypes] = useState([]);
  const [showNoisy, setShowNoisy] = useState(false);
  const [compareTo, setCompareTo] = useState('prev');
  const [adhoc, setAdhoc] = useState(null);
  const [expanded, setExpanded] = useState({});

  useEffect(() => {
    setData(null);
    setError(null);
    const q = new URLSearchParams();
    if (run) q.set('run', run);
    if (project) q.set('project', project);
    if (showNoisy) q.set('noisy', '1');
    types.forEach((t) => q.append('type', t));
    authFetch(`/api/changes?${q}`)
      .then((r) => r.json())
      .then((d) => (d.error ? setError(d.error) : setData(d)))
      .catch((e) => setError(e.message));
  }, [run, project, showNoisy, types.join(',')]);

  useEffect(() => {
    if (compareTo === 'prev') { setAdhoc(null); return; }
    const q = new URLSearchParams({ from: compareTo });
    if (run) q.set('to', run);
    if (project) q.set('project', project);
    authFetch(`/api/diff?${q}`).then((r) => r.json()).then(setAdhoc).catch(() => setAdhoc(null));
  }, [compareTo, run, project]);

  if (error) {
    return html`<div class="view-scroll"><div class="empty">
      <h2>Nothing to compare</h2><p class="muted">${error}</p></div></div>`;
  }
  if (!data) return html`<div class="loading">Loading…</div>`;

  const summary = (adhoc && adhoc.summary) || data.summary || {};

  if (summary.baseline) {
    return html`<div class="view-scroll"><div class="empty">
      <h2>This is the first scan</h2>
      <p class="muted">${summary.note
        || 'There is nothing earlier to compare against.'}</p>
      <button class="btn btn-primary" onClick=${() => onNavigate('runs')}>
        Upload another scan</button>
    </div></div>`;
  }

  const toggleType = (t) => setTypes(
    types.includes(t) ? types.filter((x) => x !== t) : [...types, t]);

  const shown = data.assets.filter(
    (a) => !types.length || types.includes(a.change_type));

  return html`<div class="view">
    <div class="toolbar">
      <span class="muted" style="font-size:11px">Compare</span>
      <select class="input" value=${compareTo}
        onChange=${(e) => setCompareTo(e.target.value)}>
        <option value="prev">against the previous scan</option>
        <option value="first">against the first scan (cumulative drift)</option>
      </select>
      ${Object.entries(TYPE_META).map(([key, meta]) => html`
        <button class="btn btn-sm"
          style=${types.includes(key)
            ? `border-color:${meta.token};color:${meta.token}` : ''}
          onClick=${() => toggleType(key)}>
          ${meta.glyph} ${meta.label} ${num(summary[key] ?? 0)}
        </button>`)}
      <span class="spacer"></span>
      <label class="facet-row" style="width:auto">
        <input type="checkbox" checked=${showNoisy}
          onChange=${(e) => setShowNoisy(e.target.checked)} />
        <span class="label">Show noisy fields</span>
      </label>
    </div>

    <div class="view-scroll">
      ${data.previous_run && html`<div class="muted"
        style="font-size:12px;margin-bottom:10px">
        ${adhoc
          ? `${adhoc.from ? (adhoc.from.label || adhoc.from.run_key) : '?'} → ${
              adhoc.to.label || adhoc.to.run_key}`
          : `${data.previous_run.label || data.previous_run.run_key} → ${
              data.run.label || data.run.run_key}`}
      </div>`}

      ${data.rules_changed ? html`<div class="banner">
        <span>▲</span>
        <div><strong>The scoring rules changed between these runs.</strong>
        Some score and band differences below may be a result of re-scoring
        rather than anything changing in the real world.</div>
      </div>` : null}

      <div class="grid-cards" style="margin-bottom:14px">
        ${Object.entries(TYPE_META).map(([key, meta]) => html`
          <div class="card kpi">
            <div class="kpi-value" style=${`color:${meta.token}`}>
              ${num(summary[key] ?? 0)}</div>
            <div class="kpi-label">${meta.label}</div>
            ${key === 'returned' && (summary.returned ?? 0) > 0 && html`
              <div class="kpi-note">Seen before, gone, and now back — counted
                separately so they do not read as new discoveries.</div>`}
            ${key === 'added' && html`<div class="kpi-note">
              Genuinely first seen in this scan.</div>`}
          </div>`)}
        <div class="card kpi">
          <div class="kpi-value">${num(summary.unchanged ?? 0)}</div>
          <div class="kpi-label">Unchanged</div>
        </div>
      </div>

      <div class="card" style="margin-bottom:14px">
        <h3>Direction of travel</h3>
        <div class="chip-list">
          <${DirectionChip} direction="worse" />
          <span class="num">${num(summary.worse ?? 0)} field changes</span>
          <${DirectionChip} direction="better" />
          <span class="num">${num(summary.better ?? 0)}</span>
          <${DirectionChip} direction="lateral" />
          <span class="num">${num(summary.lateral ?? 0)}</span>
        </div>
        <div class="kpi-note" style="margin-top:6px">
          Counts material changes only. Noisy fields and reclassifications are
          excluded, otherwise a handful of rotated IPs would read the same as a
          lost firewall.
        </div>
        ${Object.keys(summary.by_field || {}).length ? html`<div style="margin-top:10px">
          <div class="kpi-label" style="margin-bottom:4px">Which fields moved</div>
          <div class="chip-list">
            ${Object.entries(summary.by_field).slice(0, 12).map(([f, n]) => html`
              <span class="chip">${f.replace(/_/g, ' ')} <strong>${n}</strong></span>`)}
          </div>
        </div>` : null}
      </div>

      ${(summary.classification_changes ?? 0) > 0 ? html`<div class="banner info">
        <span>i</span>
        <div>${summary.classification_changes} change(s) are to how frogscope
        <em>classifies</em> an asset — its environment or zone — rather than to
        the asset itself. They are listed separately so a config edit never reads
        as infrastructure or attacker activity.</div>
      </div>` : null}

      ${data.flapping.length ? html`<div class="card" style="margin-bottom:14px">
        <${CardTitle} topic="changes.flapping">Unstable assets (${data.flapping.length})<//>
        <p class="muted" style="margin-top:0">
          These come and go between scans — autoscaled hosts, or names that drift
          in and out of scope. They are excluded from the headline counts above,
          because chasing them every week is how a change feed loses its
          audience.
        </p>
        <div class="scroll-x"><table class="plain">
          <thead><tr><th>Endpoint</th><th>Presence</th>
            <th class="right">Toggles</th><th>State</th></tr></thead>
          <tbody>${data.flapping.slice(0, 20).map((f) => html`<tr>
            <td class="mono">${f.asset_key}</td>
            <td class="mono" title="oldest run first">${
              f.presence.split('').map((c) => (c === '1' ? '●' : '○')).join('')}</td>
            <td class="num right">${f.flap_count}</td>
            <td>${titleCase(f.stability || '')}</td>
          </tr>`)}</tbody>
        </table></div>
      </div>` : null}

      <div class="card">
        <${CardTitle} topic="changes.diff">What changed (${shown.length} asset${shown.length === 1 ? '' : 's'})<//>
        ${!shown.length && html`<p class="subtle">Nothing matches these filters.</p>`}
        ${shown.slice(0, 200).map((asset) => {
          const meta = TYPE_META[asset.change_type] || TYPE_META.modified;
          const open = expanded[asset.asset_key];
          return html`<div class="exec-theme">
            <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;
                        cursor:pointer"
                 onClick=${() => setExpanded({ ...expanded,
                   [asset.asset_key]: !open })}>
              <span class="chip" style=${`color:${meta.token};border-color:${meta.token}`}>
                ${meta.glyph} ${meta.label}</span>
              ${asset.worst_severity !== 'info'
                && html`<${SeverityChip} severity=${asset.worst_severity} />`}
              ${asset.change_type === 'modified'
                && html`<${DirectionChip} direction=${asset.direction} />`}
              <code style="flex:1;min-width:200px">${asset.asset_key}</code>
              ${asset.fields.length
                ? html`<span class="subtle">${asset.fields.length} field${
                    asset.fields.length === 1 ? '' : 's'} ${open ? '▾' : '▸'}</span>`
                : null}
            </div>
            ${open && asset.fields.length ? html`<div style="margin-top:6px">
              <table class="plain">
                <tbody>${asset.fields.map((f) => html`<tr>
                  <td style="width:150px"><code>${f.field}</code>
                    ${f.is_noisy ? html`<span class="chip subtle">noisy</span>` : ''}
                    ${f.is_classification
                      ? html`<span class="chip subtle">classification</span>` : ''}</td>
                  <td>${f.summary}
                    ${f.added && f.added.length ? html`<div style="font-size:11px"
                      class="subtle">gained: ${f.added.join(', ')}</div>` : null}
                    ${f.removed && f.removed.length ? html`<div style="font-size:11px"
                      class="subtle">lost: ${f.removed.join(', ')}</div>` : null}</td>
                </tr>`)}</tbody>
              </table>
              <button class="btn btn-sm" style="margin-top:6px"
                onClick=${(e) => { e.stopPropagation();
                  onNavigate('endpoints', {
                    filters: { endpoint_key: [`~${asset.asset_key}`] } }); }}>
                Open in the grid</button>
            </div>` : null}
          </div>`;
        })}
        ${shown.length > 200 && html`<p class="subtle" style="margin-top:8px">
          Showing the first 200 of ${shown.length}.</p>`}
      </div>
    </div>
  </div>`;
}

// ── Trends ──────────────────────────────────────────────────────────────────

// Metrics where a higher number is better, so the arrow has to flip.
const HIGHER_IS_BETTER = new Set(['posture_index_host', 'posture_index_endpoint',
                                  'hosts_clean']);

function Delta({ points, metric }) {
  if (!points || points.length < 2) {
    return html`<span class="stat-empty">no prior scan</span>`;
  }
  const first = points[points.length - 2].value;
  const last = points[points.length - 1].value;
  const change = last - first;
  if (Math.abs(change) < 0.05) {
    return html`<span class="subtle" style="font-size:11px">no change</span>`;
  }
  const higherBetter = HIGHER_IS_BETTER.has(metric);
  const good = higherBetter ? change > 0 : change < 0;
  const token = good ? 'var(--status-good)' : 'var(--status-critical)';
  const arrow = change > 0 ? '▲' : '▼';
  const formatted = Number.isInteger(change) ? change : change.toFixed(1);
  return html`<span style=${`color:${token};font-size:12px;font-weight:600`}>
    ${arrow} ${change > 0 ? '+' : ''}${formatted}</span>`;
}

export function TrendsView({ project, onNavigate }) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    const q = new URLSearchParams();
    if (project) q.set('project', project);
    authFetch(`/api/trends?${q}`)
      .then((r) => r.json())
      .then((d) => (d.error ? setError(d.error) : setData(d)))
      .catch((e) => setError(e.message));
  }, [project]);

  if (error) {
    return html`<div class="view-scroll"><div class="banner error">${error}</div></div>`;
  }
  if (!data) return html`<div class="loading">Loading…</div>`;

  if (!data.enough_runs) {
    // Said plainly rather than drawn as a flat line, which would read as
    // "nothing changed" when the truth is "nothing to compare".
    return html`<div class="view-scroll"><div class="empty">
      <h2>Trends need at least two scans</h2>
      <p class="muted">${data.runs.length} scan ingested so far. Upload another
        and every metric below gets a line.</p>
      <button class="btn btn-primary" onClick=${() => onNavigate('runs')}>
        Upload a scan</button>
    </div></div>`;
  }

  const entries = Object.entries(data.metrics);
  const groups = [
    ['Posture', ['posture_index_host', 'posture_index_endpoint',
                 'hosts_needing_attention']],
    ['Findings', ['findings_total', 'findings_critical', 'findings_high']],
    ['Surface', ['hosts', 'real_endpoints', 'no_waf_hosts',
                 'origin_exposed_hosts', 'nonprod_exposed']],
    ['Specific exposures', ['remote_access', 'mgmt_surfaces', 'eol_hosts',
                            'takeover_candidates']],
    ['Churn', ['changes_added', 'changes_removed', 'changes_modified']],
  ];

  const anyIncomplete = data.runs.some((r) => r.incomplete);
  const rulesChanged = new Set(data.runs.map((r) => r.rules_hash).filter(Boolean)).size > 1;

  return html`<div class="view-scroll">
    <div class="muted" style="font-size:12px;margin-bottom:10px">
      ${data.runs.length} scans, ${when(data.runs[0].started_at)} to
      ${when(data.runs[data.runs.length - 1].started_at)}
    </div>

    ${anyIncomplete ? html`<div class="banner">
      <span>▲</span>
      <div>At least one scan in this series was flagged as possibly incomplete.
      A truncated scan shows up as an improvement it did not earn, so treat any
      dip with suspicion.</div>
    </div>` : null}

    ${rulesChanged ? html`<div class="banner">
      <span>▲</span>
      <div>The scoring rules changed during this series. Movement in score-based
      metrics may be re-scoring rather than a real-world change. Run
      <code>frogscope rescore --run all</code> to put every scan on the current
      rules.</div>
    </div>` : null}

    ${groups.map(([title, keys]) => {
      const present = keys.filter((k) => data.metrics[k]);
      if (!present.length) return null;
      return html`<div class="card">
        <h3>${title}</h3>
        <div class="grid-cards">
          ${present.map((key) => {
            const metric = data.metrics[key];
            const values = metric.points.map((p) => p.value);
            const last = values[values.length - 1];
            return html`<div class="card kpi">
              <div style="display:flex;align-items:baseline;gap:8px">
                <span class="kpi-value" style="font-size:22px">${
                  Number.isInteger(last) ? num(last) : last.toFixed(1)}</span>
                <${Delta} points=${metric.points} metric=${key} />
              </div>
              <div class="kpi-label">${metric.label}</div>
              <${Sparkline} points=${values} width=${120} height=${28}
                colour=${HIGHER_IS_BETTER.has(key)
                  ? 'var(--status-good)' : seriesColour(0)} />
              <div class="kpi-note">${values.map((v) =>
                Number.isInteger(v) ? v : v.toFixed(1)).join(' → ')}</div>
            </div>`;
          })}
        </div>
      </div>`;
    })}

    <div class="card">
      <h3>Reading these</h3>
      <p class="muted" style="margin-top:0">
        A rising absolute count with a flat index means the estate is growing and
        the new assets are about as healthy as the existing ones — worth knowing,
        and easy to miss if you only watch the index.
      </p>
      <p class="muted" style="margin-bottom:0">
        Churn metrics count assets appearing and disappearing. Assets that toggle
        repeatedly are excluded from those counts and listed under Changes as
        unstable instead.
      </p>
    </div>
  </div>`;
}

// ── Endpoint history, for the drawer ────────────────────────────────────────

export function EndpointHistory({ endpointKey, run, project }) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    setData(null);
    const q = new URLSearchParams();
    if (run) q.set('run', run);
    if (project) q.set('project', project);
    authFetch(`/api/history/${encodeURIComponent(endpointKey)}?${q}`)
      .then((r) => r.json())
      .then((d) => (d.error ? setError(d.error) : setData(d)))
      .catch((e) => setError(e.message));
  }, [endpointKey, run, project]);

  if (error) return html`<div class="banner">${error}</div>`;
  if (!data) return html`<div class="loading">Loading…</div>`;

  const presence = data.presence;
  const scores = data.scores || [];

  return html`<div>
    ${presence ? html`<dl class="kv">
      <dt>Seen in</dt>
      <dd>${presence.runs_seen} of ${presence.presence.length} scans
        <span class="mono" style="margin-left:6px" title="oldest scan first">
          ${presence.presence.split('').map((c) => (c === '1' ? '●' : '○')).join('')}
        </span></dd>
      <dt>Stability</dt>
      <dd>${titleCase(presence.stability || 'unknown')}
        ${presence.is_flapping ? html` <span class="chip" data-state="warn">
          ▲ comes and goes</span>` : ''}</dd>
    </dl>` : html`<p class="subtle">No history recorded yet.</p>`}

    ${scores.length > 1 ? html`<div style="margin-top:14px">
      <div class="kpi-label" style="margin-bottom:4px">Risk score across scans</div>
      <${Sparkline} points=${scores.map((s) => s.score)} width=${200} height=${34} />
      <div class="kpi-note">${scores.map((s) =>
        `${s.label || s.run_key}: ${s.score}`).join(' · ')}</div>
    </div>` : null}

    ${data.changes.length ? html`<div style="margin-top:14px">
      <div class="kpi-label" style="margin-bottom:4px">
        When each attribute last changed</div>
      <div class="scroll-x"><table class="plain">
        <thead><tr><th>Scan</th><th>Field</th><th>New value</th></tr></thead>
        <tbody>${data.changes.slice(-40).reverse().map((c) => html`<tr>
          <td class="nowrap">${c.label || c.run_key}</td>
          <td><code>${c.field}</code></td>
          <td style="overflow-wrap:anywhere">${
            Array.isArray(c.value) ? c.value.join(', ') : String(c.value ?? '')}</td>
        </tr>`)}</tbody>
      </table></div>
      <div class="kpi-note" style="margin-top:4px">
        Only actual changes are stored, so this is the complete timeline rather
        than a value per scan.
      </div>
    </div>` : html`<p class="subtle" style="margin-top:14px">
      No attribute changes recorded for this endpoint.</p>`}
  </div>`;
}
