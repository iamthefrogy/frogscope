// Findings and Methodology views, and the score-trace waterfall.
//
// Severity is never carried by colour alone: every chip pairs a glyph and a text
// label with its colour, because several status steps are deliberately low
// contrast and colour-blind readers must get the same information.

import { h } from 'preact';
import { useEffect, useMemo, useState } from 'preact/hooks';
import htm from 'htm';
import { authFetch, store } from './store.js';
import { num, titleCase } from './lib.js';
import { CardTitle } from './help.js';

const html = htm.bind(h);

export const SEVERITY = {
  critical: { label: 'Critical', glyph: '!!', token: 'var(--status-critical)' },
  high:     { label: 'High',     glyph: '!',  token: 'var(--status-high)' },
  medium:   { label: 'Medium',   glyph: '~',  token: 'var(--status-medium)' },
  low:      { label: 'Low',      glyph: '·',  token: 'var(--status-low)' },
  info:     { label: 'Info',     glyph: ' ',  token: 'var(--color-text-subtle)' },
};

const CONFIDENCE_NOTE = {
  confirmed: 'Directly observed in the scan data.',
  probable: 'Strongly indicated by fingerprinting, but not directly confirmed.',
  possible: 'A product or pattern known to carry this risk was detected. This is '
          + 'a prompt to check, not evidence of an exploitable instance.',
};

export function SeverityChip({ severity, count }) {
  const meta = SEVERITY[severity] || SEVERITY.info;
  return html`<span class="chip" style=${`color:${meta.token};border-color:${meta.token}`}>
    <strong>${meta.glyph}</strong> ${meta.label}${count !== undefined ? ` ${count}` : ''}
  </span>`;
}

function ConfidenceChip({ confidence }) {
  return html`<span class="chip" title=${CONFIDENCE_NOTE[confidence] || ''}>
    ${titleCase(confidence)}
  </span>`;
}

// ── Score waterfall ─────────────────────────────────────────────────────────

export function ScoreTrace({ endpointKey, run, project }) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    setData(null);
    authFetch(`/api/score/${encodeURIComponent(endpointKey)}`
          + `${run ? `?run=${encodeURIComponent(run)}` : ''}`)
      .then((r) => r.json())
      .then((d) => (d.error ? setError(d.error) : setData(d)))
      .catch((e) => setError(e.message));
  }, [endpointKey, run, project]);

  if (error) return html`<div class="banner">${error}</div>`;
  if (!data) return html`<div class="loading">Loading…</div>`;

  if (data.excluded) {
    return html`<div class="banner info">
      <span>∅</span>
      <div><strong>Not scored.</strong> Excluded by ${data.excluded_by} —
      httpx probed a TLS-only port over cleartext, so the 400 response is the
      server behaving correctly rather than a finding.</div>
    </div>`;
  }

  const contributions = data.contributions || [];
  const modifiers = data.modifiers || [];
  const skipped = data.skipped || [];
  const positives = contributions.filter((c) => c.family === 'positive');
  const scoring = contributions.filter((c) => c.family !== 'positive');
  const widest = Math.max(1, ...scoring.map((c) => c.points_applied));

  return html`<div>
    <div style="display:flex;gap:20px;align-items:baseline;margin-bottom:6px">
      <div>
        <div class="kpi-value" style="font-size:32px">${data.score}<span
          class="muted" style="font-size:15px">/100</span></div>
        <div class="kpi-label">Risk score</div>
      </div>
      <div>
        <${SeverityChip} severity=${data.band} />
        <div class="kpi-note">Endpoint overall</div>
      </div>
      ${data.worst_severity && html`<div>
        <${SeverityChip} severity=${data.worst_severity} />
        <div class="kpi-note">Worst single issue</div>
      </div>`}
    </div>

    ${data.floored_from ? html`<div class="banner" style="margin-top:10px">
      <span>▲</span>
      <div>Raised from <strong>${data.floored_from}</strong> to
      <strong>${data.band}</strong> by the severity floor: a critical rule fired
      and nothing mitigated it.</div>
    </div>` : null}

    ${data.mitigated ? html`<div class="banner info" style="margin-top:10px">
      <span>🛡</span>
      <div>This score was reduced because a control is in place — see the
      multipliers below. The underlying findings still carry their own severity
      and appear in the Findings view, so nothing is hidden.</div>
    </div>` : null}

    <div style="margin:14px 0">
      ${Object.entries(data.buckets_meta || {}).map(([name, meta]) => {
        const value = data[name] ?? 0;
        const cap = meta.cap || 100;
        return html`<div style="margin-bottom:6px">
          <div style="display:flex;justify-content:space-between;font-size:12px">
            <span>${meta.label} <span class="subtle">— ${meta.exec_label}</span></span>
            <span class="num">${value} / ${cap}${value >= cap ? ' (at cap)' : ''}</span>
          </div>
          <div class="fill-bar"><span style=${
            `width:${Math.min(100, (100 * value) / cap)}%`}></span></div>
        </div>`;
      })}
    </div>

    <h3 style="font-size:12px;color:var(--color-text-muted)">How the score was built</h3>
    <table class="plain">
      <tbody>
        ${scoring.map((entry) => html`<tr>
          <td class="num right" style="width:56px;font-weight:600">
            +${entry.points_applied}</td>
          <td style="width:34px"><span style=${
            `color:${(SEVERITY[entry.severity] || SEVERITY.info).token}`}>${
            (SEVERITY[entry.severity] || SEVERITY.info).glyph}</span></td>
          <td>
            <code>${entry.rule_id}</code>
            <div class="subtle" style="font-size:11px">
              ${entry.bucket}
              ${entry.family_discounted
                ? ' · overlapping symptom, counted at 30%' : ''}
              ${entry.capped ? ' · bucket cap reached' : ''}
              ${entry.points_raw !== entry.points_applied
                ? ` · full weight ${entry.points_raw}` : ''}
            </div>
          </td>
          <td style="width:120px">
            <div class="fill-bar"><span style=${
              `width:${(100 * entry.points_applied) / widest}%;background:${
                (SEVERITY[entry.severity] || SEVERITY.info).token}`}></span></div>
          </td>
        </tr>`)}
        <tr>
          <td class="num right" style="font-weight:700">${data.raw_score}</td>
          <td></td><td class="muted">subtotal after bucket caps</td><td></td>
        </tr>
        ${modifiers.map((m) => html`<tr>
          <td class="num right" style="font-weight:600">×${m.factor}</td>
          <td></td>
          <td><code>${m.id}</code>
            <div class="subtle" style="font-size:11px">${m.reason}</div></td>
          <td></td>
        </tr>`)}
        ${modifiers.length ? html`<tr>
          <td class="num right" style="font-weight:700">${data.score}</td>
          <td></td><td class="muted">final</td><td></td>
        </tr>` : null}
      </tbody>
    </table>

    ${positives.length ? html`<div style="margin-top:14px">
      <h3 style="font-size:12px;color:var(--color-text-muted)">Controls in place</h3>
      <div class="chip-list">
        ${positives.map((p) => html`<span class="chip" data-state="good"
          title=${p.why}>✓ ${p.title}</span>`)}
      </div>
    </div>` : null}

    <div style="margin-top:16px">
      <h3 style="font-size:12px;color:var(--color-text-muted)">Why each rule fired</h3>
      ${scoring.map((entry) => html`<div style="margin-bottom:12px">
        <div style="display:flex;gap:6px;align-items:center;flex-wrap:wrap">
          <${SeverityChip} severity=${entry.severity} />
          <${ConfidenceChip} confidence=${entry.confidence} />
          <strong>${entry.title}</strong>
        </div>
        ${entry.why && html`<div style="margin-top:3px">${entry.why}</div>`}
        ${Object.keys(entry.evidence || {}).length ? html`
          <div class="subtle" style="font-size:11px;margin-top:2px">
            observed: ${Object.entries(entry.evidence)
              .map(([k, v]) => `${k}=${JSON.stringify(v)}`).join(', ')}
          </div>` : null}
        ${entry.remediation && html`<div class="muted"
          style="font-size:12px;margin-top:2px">Fix: ${entry.remediation}</div>`}
      </div>`)}
    </div>

    ${skipped.length ? html`<div class="banner info" style="margin-top:12px">
      <span>◌</span>
      <div><strong>${skipped.length} rule(s) could not be evaluated</strong> because
        this scan did not collect the data they need. They are skipped, never
        scored as a problem — awarding points for absent data would make every
        endpoint rank the same.
        <ul style="margin:6px 0 0;padding-left:18px">
          ${skipped.map((s) => html`<li><code>${s.rule_id}</code> needs
            ${s.missing_fields.join(', ')}</li>`)}
        </ul>
        <div style="margin-top:4px">See Coverage for the httpx flags that would
        fill these in.</div>
      </div>
    </div>` : null}

    <div class="subtle" style="font-size:11px;margin-top:12px">
      Data coverage ${Math.round((data.coverage || 0) * 100)}% —
      ${data.confidence} confidence. A low score on thin data is not the same as
      a clean bill of health.
    </div>
  </div>`;
}

// ── Findings view ───────────────────────────────────────────────────────────

export function FindingsView({ project, onNavigate }) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [severities, setSeverities] = useState([]);
  const [status, setStatus] = useState('open');
  const [expanded, setExpanded] = useState({});
  const [busy, setBusy] = useState(false);

  const load = () => {
    const params = new URLSearchParams();
    if (project) params.set('project', project);
    severities.forEach((s) => params.append('severity', s));
    if (status) params.set('status', status);
    authFetch(`/api/findings?${params}`)
      .then((r) => r.json())
      .then((d) => (d.error ? setError(d.error) : setData(d)))
      .catch((e) => setError(e.message));
  };

  useEffect(() => { setData(null); load(); },
    [project, severities.join(','), status]);

  const setFindingStatus = async (id, next) => {
    setBusy(true);
    await authFetch(`/api/findings/${id}/status`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: next }),
    });
    setBusy(false);
    load();
  };

  if (error) {
    return html`<div class="view-scroll"><div class="empty">
      <h2>No findings yet</h2><p class="muted">${error}</p></div></div>`;
  }
  if (!data) return html`<div class="loading">Loading…</div>`;

  const toggle = (severity) => setSeverities(
    severities.includes(severity)
      ? severities.filter((s) => s !== severity)
      : [...severities, severity]);

  return html`<div class="view">
    <div class="toolbar">
      <span class="muted" style="font-size:11px">Severity</span>
      ${Object.keys(SEVERITY).map((s) => {
        const on = severities.includes(s);
        const meta = SEVERITY[s];
        return html`<button class="btn btn-sm"
          style=${on ? `border-color:${meta.token};color:${meta.token}` : ''}
          onClick=${() => toggle(s)}>
          ${meta.glyph} ${meta.label} ${data.by_severity[s] || 0}
        </button>`;
      })}
      <span class="spacer"></span>
      <select class="input" value=${status}
        onChange=${(e) => setStatus(e.target.value)}>
        <option value="open">Open (${data.open})</option>
        <option value="ack">Acknowledged (${data.acknowledged})</option>
        <option value="resolved">Resolved (${data.resolved})</option>
        <option value="">All statuses</option>
      </select>
      <button class="btn btn-sm" onClick=${() => copyAllHosts(data)}>
        Copy all hosts</button>
    </div>

    <div class="view-scroll">
      <div class="banner info">
        <span>i</span>
        <div>Findings are grouped per rule and deduplicated per host, so a
        Cloudflare-fronted host appears once rather than once per alias port.
        Severity comes from the rule, not from the endpoint's score — a critical
        issue on an otherwise unremarkable host still shows as critical.</div>
      </div>

      ${!data.grouped.length && html`<div class="empty">
        <h2>Nothing matches</h2>
        <p class="muted">No findings with these filters.</p></div>`}

      ${data.grouped.map((group) => {
        const open = expanded[group.rule_id];
        const rule = group.rule || {};
        return html`<div class="card" style="margin-bottom:10px">
          <div style="display:flex;gap:8px;align-items:center;cursor:pointer;flex-wrap:wrap"
               onClick=${() => setExpanded({ ...expanded,
                 [group.rule_id]: !open })}>
            <${SeverityChip} severity=${group.severity} />
            <${ConfidenceChip} confidence=${group.confidence} />
            <strong style="flex:1;min-width:200px">${group.title}</strong>
            <span class="chip">${group.host_count} host${
              group.host_count === 1 ? '' : 's'}</span>
            <span class="chip">${group.endpoint_count} endpoint${
              group.endpoint_count === 1 ? '' : 's'}</span>
            <span class="subtle">${open ? '▾' : '▸'}</span>
          </div>

          ${open && html`<div style="margin-top:12px">
            ${rule.why && html`<p style="margin:0 0 8px">${rule.why}</p>`}
            ${rule.remediation && html`<p class="muted" style="margin:0 0 8px">
              <strong>Fix:</strong> ${rule.remediation}</p>`}

            <div class="subtle" style="font-size:11px;margin-bottom:8px">
              <code>${group.rule_id}</code> · weight ${
                rule.points ?? 'variable'} in the${' '}
              <em>${rule.bucket}</em> bucket · fires when ${rule.condition}
            </div>

            <div class="scroll-x"><table class="plain">
              <thead><tr><th>Host</th><th class="right">Endpoints</th>
                <th class="right">Score</th><th>Status</th><th></th></tr></thead>
              <tbody>
                ${group.findings.map((f) => html`<tr>
                  <td><a href="#" onClick=${(e) => {
                    e.preventDefault();
                    onNavigate('endpoints', { filters: { host: [f.asset_key] } });
                  }}>${f.asset_key}</a></td>
                  <td class="num right">${f.detail.endpoint_count || 0}</td>
                  <td class="num right">${f.detail.max_score || 0}</td>
                  <td><span class="chip">${f.status}</span></td>
                  <td class="right">
                    ${f.status !== 'ack' && html`<button class="btn btn-sm"
                      disabled=${busy}
                      onClick=${() => setFindingStatus(f.id, 'ack')}>Ack</button>`}
                    ${f.status === 'ack' && html`<button class="btn btn-sm"
                      disabled=${busy}
                      onClick=${() => setFindingStatus(f.id, 'open')}>Reopen</button>`}
                  </td>
                </tr>`)}
              </tbody>
            </table></div>

            <button class="btn btn-sm" style="margin-top:8px"
              onClick=${() => navigator.clipboard.writeText(
                group.findings.map((f) => f.asset_key).join('\n'))}>
              Copy affected hosts</button>
          </div>`}
        </div>`;
      })}
    </div>
  </div>`;
}

function copyAllHosts(data) {
  const hosts = [...new Set((data.findings || []).map((f) => f.asset_key))];
  navigator.clipboard.writeText(hosts.join('\n'));
}

// ── Methodology view ────────────────────────────────────────────────────────

export function MethodologyView({ run, project }) {
  const [rules, setRules] = useState(null);
  const [risk, setRisk] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    const q = new URLSearchParams();
    if (run) q.set('run', run);
    if (project) q.set('project', project);
    Promise.all([
      authFetch(`/api/rules?${q}`).then((r) => r.json()),
      authFetch(`/api/risk?${q}`).then((r) => r.json()),
    ]).then(([a, b]) => { setRules(a); setRisk(b.error ? null : b); })
      .catch((e) => setError(e.message));
  }, [run, project]);

  if (error) return html`<div class="view-scroll"><div class="banner error">${error}</div></div>`;
  if (!rules) return html`<div class="loading">Loading…</div>`;

  const scoring = (rules.rules || []).filter((r) => r.family !== 'positive');
  const positives = (rules.rules || []).filter((r) => r.family === 'positive');
  const inert = scoring.filter((r) => r.reserved);
  const live = scoring.filter((r) => !r.reserved);

  return html`<div class="view-scroll">
    <div class="card" style="margin-bottom:14px">
      <${CardTitle} topic="method.rules">How the score works<//>
      <p style="margin-top:0">
        Each endpoint is checked against every rule. A matching rule adds its
        weight to one of three buckets, each with its own cap. The subtotal is
        then multiplied by any modifiers that apply, and the result is banded.
      </p>
      <div class="grid-cards" style="margin:10px 0">
        ${Object.entries(rules.buckets || {}).map(([name, meta]) => html`
          <div class="card">
            <div class="kpi-value" style="font-size:20px">${meta.cap}</div>
            <div class="kpi-label">${meta.label} cap</div>
            <div class="kpi-note">${meta.exec_label}</div>
          </div>`)}
      </div>
      <dl class="kv">
        <dt>Overlapping symptoms</dt>
        <dd>Within one family, only the highest-weight rule counts in full;
          the rest count at ${Math.round((rules.overlap_factor || 0.3) * 100)}%.
          Three symptoms of one underlying problem should not score triple.</dd>
        <dt>Modifier floor</dt>
        <dd>Modifiers multiply, so a WAF (×0.45) on a Cloudflare alias port
          (×0.25) would compound to ×0.11 and erase the score. The combined
          product is clamped at ×${rules.modifier_floor}: a mitigation reduces
          urgency, it does not delete a finding.</dd>
        <dt>Severity floor</dt>
        <dd>A critical rule cannot land in a trivial band — but only when nothing
          mitigating applied. If a WAF is genuinely blocking the request, the
          lower score is the honest answer, and the finding still carries
          critical severity in the Findings view.</dd>
        <dt>Missing data</dt>
        <dd>A rule whose inputs this scan did not collect is <em>skipped and
          reported</em>, never scored as a problem. Awarding points for absent
          data would rank every endpoint identically.</dd>
      </dl>
    </div>

    <div class="card" style="margin-bottom:14px">
      <h3>Bands</h3>
      <table class="plain">
        <thead><tr><th>Band</th><th class="right">Score from</th>
          <th class="right">Endpoints</th></tr></thead>
        <tbody>${(rules.bands || []).map((band) => html`<tr>
          <td><${SeverityChip} severity=${band.name} /></td>
          <td class="num right">${band.min}</td>
          <td class="num right">${
            (risk && risk.by_band && risk.by_band[band.name]) || 0}</td>
        </tr>`)}</tbody>
      </table>
      <p class="muted" style="font-size:12px;margin-bottom:0">
        Thresholds are calibrated to what this rule set actually produces, not to
        a notional 0-100. Run <code>frogscope rules coverage</code> after changing
        a weight — it warns when a band is empty or swallows the majority.
      </p>
    </div>

    ${risk && risk.residual_risk && risk.residual_risk.formula ? html`
      <div class="card" style="margin-bottom:14px">
        <h3>Residual risk index</h3>
        <div style="display:flex;gap:16px;align-items:baseline">
          <div class="kpi-value">${risk.residual_risk.index}<span class="muted"
            style="font-size:15px">/100</span></div>
          <div class="muted">higher is better</div>
        </div>
        <p class="muted" style="font-size:12px;margin-bottom:0">
          ${risk.residual_risk.formula}
        </p>
      </div>` : null}

    <div class="card" style="margin-bottom:14px">
      <h3>Active rules (${live.length})</h3>
      <div class="scroll-x"><table class="plain">
        <thead><tr><th>Severity</th><th>Confidence</th><th>Rule</th>
          <th class="right">Weight</th><th>Bucket</th>
          <th class="right">Hosts hit</th><th>Fires when</th></tr></thead>
        <tbody>
          ${live.map((rule) => html`<tr>
            <td><${SeverityChip} severity=${rule.severity} /></td>
            <td><${ConfidenceChip} confidence=${rule.confidence} /></td>
            <td><code>${rule.id}</code>
              <div class="subtle" style="font-size:11px">${rule.title}</div></td>
            <td class="num right">${rule.points ?? (rule.map ? 'varies' : 'scaled')}</td>
            <td>${rule.bucket}</td>
            <td class="num right">${rule.fired_on_hosts ?? '—'}</td>
            <td class="subtle" style="font-size:11px;max-width:280px">
              ${rule.condition}</td>
          </tr>`)}
        </tbody>
      </table></div>
    </div>

    ${inert.length ? html`<div class="card" style="margin-bottom:14px">
      <h3>Rules waiting on data (${inert.length})</h3>
      <p class="muted" style="margin-top:0">
        Written and validated, but inert because this scan did not collect what
        they need. They will start evaluating automatically once it does — no code
        change required.
      </p>
      <table class="plain">
        <thead><tr><th>Severity</th><th>Rule</th><th>Needs</th></tr></thead>
        <tbody>${inert.map((rule) => html`<tr>
          <td><${SeverityChip} severity=${rule.severity} /></td>
          <td><code>${rule.id}</code>
            <div class="subtle" style="font-size:11px">${rule.title}</div></td>
          <td>${(rule.requires_fields || []).map(
            (f) => html`<code>${f}</code> `)}</td>
        </tr>`)}</tbody>
      </table>
    </div>` : null}

    <div class="card" style="margin-bottom:14px">
      <h3>Modifiers</h3>
      <table class="plain">
        <thead><tr><th class="right">Factor</th><th>Modifier</th>
          <th>Why</th></tr></thead>
        <tbody>${(rules.modifiers || []).map((m) => html`<tr>
          <td class="num right">×${m.factor}</td>
          <td><code>${m.id}</code>
            <div class="subtle" style="font-size:11px">${m.condition}</div></td>
          <td>${m.reason}</td>
        </tr>`)}</tbody>
      </table>
    </div>

    <div class="card" style="margin-bottom:14px">
      <h3>Exclusions</h3>
      ${(rules.exclusions || []).map((e) => html`<div style="margin-bottom:8px">
        <code>${e.id}</code>
        <div class="subtle" style="font-size:11px">${e.condition}</div>
        <div>${e.reason}</div>
      </div>`)}
    </div>

    ${positives.length ? html`<div class="card" style="margin-bottom:14px">
      <h3>Positive controls</h3>
      <p class="muted" style="margin-top:0">
        Zero weight — recorded so the dashboard can report what is working, not
        only what is broken.
      </p>
      <div class="chip-list">
        ${positives.map((p) => html`<span class="chip" data-state="good"
          title=${p.why}>✓ ${p.title}</span>`)}
      </div>
    </div>` : null}

    <div class="card">
      <h3>Confidence levels</h3>
      <dl class="kv">
        ${Object.entries(CONFIDENCE_NOTE).map(([level, note]) => html`
          <dt>${titleCase(level)}</dt><dd>${note}</dd>`)}
      </dl>
      <p class="muted" style="font-size:12px;margin-bottom:0">
        Everything here derives from an unauthenticated HTTP probe. It identifies
        what is probably running and reachable; it does not prove anything is
        exploitable.
      </p>
    </div>
  </div>`;
}
