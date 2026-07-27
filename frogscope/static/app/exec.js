// Executive view: one printable screen answering how big the surface is, what
// needs fixing, and what the scan could not see.
//
// The headline is a HOST count, not an index. On real data the endpoint-weighted
// index reads 94/100 while 64% of hosts carry a critical or high finding — an
// index-led page would invite exactly the wrong conclusion. Both numbers are
// shown, with their basis stated.

import { h } from 'preact';
import { useEffect, useState } from 'preact/hooks';
import htm from 'htm';
import {
  GroupedBars, Legend, Meter, RankedBars, SEVERITY_TOKEN,
  SeverityBar, Sparkline, StackedShareBar, seriesColour,
} from './charts.js';
import { num, when } from './lib.js';
import { SeverityChip } from './risk.js';
import { CardTitle } from './help.js';
import { authFetch, store } from './store.js';

const html = htm.bind(h);

// Metrics where a higher number is better, so the arrow direction flips.
const HIGHER_IS_BETTER = new Set(['posture_index_host', 'posture_index_endpoint']);

function trendFor(trends, metric) {
  const entry = trends && trends.metrics && trends.metrics[metric];
  return entry ? entry.points.map((p) => p.value) : null;
}

/** Delta chip against the previous scan, or an honest note when there isn't one. */
function TrendDelta({ trends, metric }) {
  const values = trendFor(trends, metric);
  if (!values || values.length < 2) {
    return html`<span class="stat-empty">no prior scan</span>`;
  }
  const change = values[values.length - 1] - values[values.length - 2];
  if (Math.abs(change) < 0.05) {
    return html`<span class="subtle" style="font-size:11px">unchanged</span>`;
  }
  const good = HIGHER_IS_BETTER.has(metric) ? change > 0 : change < 0;
  const token = good ? 'var(--status-good)' : 'var(--status-critical)';
  const shown = Number.isInteger(change) ? change : change.toFixed(1);
  return html`<span style=${`color:${token};font-size:12px;font-weight:600`}>
    ${change > 0 ? '▲ +' : '▼ '}${shown} since last scan</span>`;
}

const PROTECTION_COLOUR = {
  waf: 'var(--status-good)',
  platform: seriesColour(3),
  none: 'var(--status-critical)',
  not_serving: 'var(--color-text-subtle)',
};

export function ExecView({ run, project, onNavigate }) {
  const [data, setData] = useState(null);
  const [trends, setTrends] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    setData(null);
    setError(null);
    const q = new URLSearchParams();
    if (run) q.set('run', run);
    if (project) q.set('project', project);
    authFetch(`/api/exec?${q}`)
      .then((r) => r.json())
      .then((d) => (d.error ? setError(d.error) : setData(d)))
      .catch((e) => setError(e.message));
    const tq = new URLSearchParams();
    if (project) tq.set('project', project);
    authFetch(`/api/trends?${tq}`).then((r) => r.json())
      .then((d) => setTrends(d.error ? null : d)).catch(() => setTrends(null));
  }, [run, project]);

  if (error) {
    return html`<div class="view-scroll"><div class="empty">
      <h2>Nothing to report yet</h2>
      <p class="muted">${error}</p>
      <button class="btn btn-primary" onClick=${() => onNavigate('runs')}>
        Upload a scan</button>
    </div></div>`;
  }
  if (!data) return html`<div class="loading">Loading…</div>`;

  const { posture, surface, protection, findings, narrative, run: meta } = data;

  return html`<div class="view-scroll exec">
    <${Header} meta=${meta} surface=${surface} />
    ${meta.incomplete ? html`<div class="banner no-print-break">
      <span>▲</span>
      <div><strong>This scan may be incomplete.</strong> It was flagged when
      ingested, so the totals below may understate the real surface.</div>
    </div>` : null}

    <${Headline} narrative=${narrative} posture=${posture}
      findings=${findings} onNavigate=${onNavigate} />

    <${Posture} posture=${posture} endpointIndex=${data.endpoint_index}
      findings=${findings} trends=${trends} />

    <${Surface} surface=${surface} protection=${protection}
      narrative=${narrative} trends=${trends} />

    <${NetworkKPIs} run=${run} project=${project} onNavigate=${onNavigate} />

    <${Themes} narrative=${narrative} onNavigate=${onNavigate} />

    <${Where} byZone=${data.by_zone} byEnv=${data.by_env} />

    <${TopHosts} hosts=${data.top_hosts} onNavigate=${onNavigate} />

    ${data.eol.products.length ? html`<${Eol} eol=${data.eol} /> ` : null}

    <${Comparison} comparison=${data.comparison} trends=${trends}
      onNavigate=${onNavigate} />

    <${Caveats} caveats=${data.caveats} onNavigate=${onNavigate} />
  </div>`;
}

// ── Network correlation (v2) ─────────────────────────────────────────────────
//
// Exactly two headline numbers, deliberately — this page is built for a
// board pack, and more than that tells an executive nothing. Fetched
// separately from the rest of the exec payload so a run with no correlation
// data doesn't slow down or complicate the page's main request.

function NetworkKPIs({ run, project, onNavigate }) {
  const [summary, setSummary] = useState(null);

  useEffect(() => {
    setSummary(null);
    store.network(run, project).then(setSummary).catch(() => setSummary(null));
  }, [run, project]);

  if (!summary) return null;

  if (!summary.correlated) {
    // The single most important addition here: without this, an
    // uncorrelated run silently reads as "the estate has no third-party
    // hosting and nothing new was found" — which is a fact about what ran,
    // not about the estate.
    return html`<div class="banner info no-print-break" style="margin-bottom:16px">
      This scan did not run "Correlate assets" — domain, IP, and certificate
      relationships (and anything only discoverable through them) are not
      reflected below.
    </div>`;
  }

  const discovered = summary.discovered_new_names || 0;
  const sharedOrUnclaimed =
    (summary.foreign_shared_ips || 0) + (summary.hosts_in_claimable_ranges || 0);

  return html`<div class="grid-cards no-print-break" style="margin-bottom:16px">
    <div class="card kpi" style="cursor:pointer" onClick=${() => onNavigate('discovered')}>
      <div class="kpi-label">Assets you didn't know about</div>
      <div class="kpi-value">${num(discovered)}</div>
      <div class="kpi-note">Found via certificate SANs and reverse DNS, never probed directly</div>
    </div>
    <div class="card kpi" style="cursor:pointer" onClick=${() => onNavigate('network')}>
      <div class="kpi-label">Hosts on shared or unrelated infrastructure</div>
      <div class="kpi-value">${num(sharedOrUnclaimed)}</div>
      <div class="kpi-note">Addresses shared with other organisations, or sitting in an unclaimed cloud range</div>
    </div>
  </div>`;
}

// ── Header ──────────────────────────────────────────────────────────────────

function Header({ meta, surface }) {
  return html`<div class="exec-header">
    <div>
      <h1 style="margin:0;font-size:20px;letter-spacing:-0.01em">
        External attack surface</h1>
    </div>
    <button class="btn no-print" onClick=${() => window.print()}>Print</button>
  </div>`;
}

// ── Headline ────────────────────────────────────────────────────────────────

function Headline({ narrative, posture, findings, onNavigate }) {
  return html`<div class="card exec-hero no-print-break">
    <div style="display:flex;gap:24px;flex-wrap:wrap;align-items:flex-start">
      <div style="flex:1;min-width:280px">
        <div style="font-size:19px;line-height:1.4;font-weight:600">
          ${narrative.headline}</div>
        ${narrative.verdict && html`<div class="muted"
          style="margin-top:6px;font-size:14px">${narrative.verdict}</div>`}
      </div>
      <div style="min-width:220px">
        <${SeverityBar} counts=${posture.by_worst_finding}
          cleanCount=${posture.clean} cleanLabel="Nothing flagged" />
        <div class="kpi-note" style="margin-top:6px">
          Every host by its most severe open finding.
        </div>
      </div>
    </div>
    <div style="display:flex;gap:8px;margin-top:12px;flex-wrap:wrap" class="no-print">
      <button class="btn btn-primary"
        onClick=${() => onNavigate('findings')}>
        Review ${num(findings.total)} findings</button>
      <button class="btn"
        onClick=${() => onNavigate('endpoints', {
          filters: { worst_severity: ['critical', 'high'] } })}>
        Open the affected endpoints</button>
    </div>
  </div>`;
}

// ── Posture ─────────────────────────────────────────────────────────────────

function Posture({ posture, endpointIndex, findings, trends }) {
  return html`<div class="card no-print-break">
    <${CardTitle} topic="exec.posture">Posture<//>
    <div class="grid-cards">
      <div class="card">
        <${Meter} value=${posture.index} label="Posture index (by host)"
          inverted=${true}
          caption="Higher is better. Weighted by each host's worst finding." />
        <${TrendDelta} trends=${trends} metric="posture_index_host" />
        <${Sparkline} points=${trendFor(trends, 'posture_index_host') || []}
          width=${110} height=${22} colour="var(--status-good)" />
      </div>
      <div class="card">
        <${Meter} value=${endpointIndex.index ?? 100}
          label="Posture index (by endpoint)" inverted=${true}
          caption="Shown for contrast only." />
      </div>
      <div class="card kpi">
        <div class="kpi-value">${num(posture.needs_attention)}</div>
        <div class="kpi-label">Hosts needing attention</div>
        <${TrendDelta} trends=${trends} metric="hosts_needing_attention" />
        <${Sparkline} points=${trendFor(trends, 'hosts_needing_attention') || []}
          width=${110} height=${22} />
        <div class="kpi-note">
          ${posture.needs_attention_pct}% of ${num(posture.total_hosts)} hosts
          have a critical or high finding.</div>
      </div>
      <div class="card kpi">
        <div class="kpi-value">${num(findings.total)}</div>
        <div class="kpi-label">Open findings</div>
        <${TrendDelta} trends=${trends} metric="findings_total" />
        <${Sparkline} points=${trendFor(trends, 'findings_total') || []}
          width=${110} height=${22} />
        <div class="kpi-note">
          Across ${num(findings.affected_hosts)} hosts, deduplicated per rule.</div>
      </div>
    </div>

    ${Math.abs((endpointIndex.index ?? 0) - posture.index) >= 15
      ? html`<div class="banner info" style="margin-top:12px">
        <span>i</span>
        <div>${`The two indices differ by `
          + `${Math.abs((endpointIndex.index ?? 0) - posture.index)} points `
          + `because a Cloudflare-fronted host contributes many near-identical `
          + `endpoints. Most endpoints are clean while most hosts still need `
          + `work. A host is the unit of remediation, so the host figure is the `
          + `one to plan against.`}</div>
      </div>` : null}
  </div>`;
}

// ── Surface ─────────────────────────────────────────────────────────────────

function Surface({ surface, protection, narrative, trends }) {
  const segments = protection.segments
    .filter((s) => s.count > 0)
    .map((s) => ({ ...s, colour: PROTECTION_COLOUR[s.key] || seriesColour(0) }));

  const composition = [
    { key: 'real', label: 'Distinct services', count: surface.real_endpoints,
      colour: seriesColour(0) },
    { key: 'alias', label: 'Cloudflare alias ports', count: surface.cf_alias_ports,
      colour: seriesColour(3) },
    { key: 'artefact', label: 'Scan artefacts', count: surface.scan_artifacts,
      colour: 'var(--color-text-subtle)' },
  ].filter((s) => s.count > 0);
  const compTotal = composition.reduce((sum, s) => sum + s.count, 0) || 1;
  composition.forEach((s) => {
    s.pct = Math.round((1000 * s.count) / compTotal) / 10;
  });

  const tiles = [
    { value: surface.no_waf_hosts, label: 'Hosts with no WAF',
      metric: 'no_waf_hosts',
      note: 'Serving content with nothing inspecting the traffic.' },
    { value: surface.origin_exposed_hosts, label: 'Reached directly',
      metric: 'origin_exposed_hosts',
      note: 'No CDN, WAF, or managed platform in the path at all.' },
    { value: surface.cdn_bypass_hosts, label: 'WAF appears bypassable',
      note: 'Protected on one port, directly reachable on another.' },
    { value: surface.remote_access, label: 'Remote-access portals',
      metric: 'remote_access',
      note: 'VPN, Citrix, or remote-desktop gateways.' },
    { value: surface.mgmt_surfaces, label: 'Management consoles',
      metric: 'mgmt_surfaces',
      note: 'Administrative interfaces reachable from the internet.' },
    { value: surface.nonprod_exposed, label: 'Non-production reachable',
      metric: 'nonprod_exposed',
      note: 'Identifiably dev, test, or UAT, and internet-facing.' },
    { value: surface.broken_origin, label: 'Broken or missing origin',
      note: 'Includes possible dangling DNS records.' },
    { value: surface.azure_app_proxy, label: 'Internal apps published',
      note: 'Deliberately exposed through Entra ID Application Proxy.' },
  ];

  return html`<div class="card no-print-break">
    <h3>The surface</h3>
    <p style="margin-top:0">${narrative.notes[0]}</p>
    <${StackedShareBar} segments=${composition}
      label="What the probe count is made of" />

    <div style="margin-top:18px">
      <${CardTitle} topic="exec.protection">What is in front of it<//>
      <${StackedShareBar} segments=${segments}
        label="Protection coverage across real endpoints" />
      ${narrative.notes[1] && html`<p class="muted"
        style="font-size:12px;margin:8px 0 0">${narrative.notes[1]}</p>`}
    </div>

    <div class="grid-cards" style="margin-top:18px">
      ${tiles.filter((t) => t.value > 0).map((t) => html`
        <div class="card kpi">
          <div class="kpi-value" style="font-size:22px">${num(t.value)}</div>
          <div class="kpi-label">${t.label}</div>
          ${t.metric && html`<${TrendDelta} trends=${trends} metric=${t.metric} />`}
          <div class="kpi-note">${t.note}</div>
        </div>`)}
    </div>
  </div>`;
}

// ── Themes ──────────────────────────────────────────────────────────────────

function Themes({ narrative, onNavigate }) {
  if (!narrative.themes.length) {
    return html`<div class="card no-print-break">
      <${CardTitle} topic="section.fix">What to fix<//>
      <p class="muted">Nothing above low severity was found.</p>
    </div>`;
  }

  return html`<div class="card no-print-break">
    <h3>What to fix, most widespread first</h3>
    ${narrative.themes.map((theme) => html`<div class="exec-theme">
      <div style="display:flex;gap:8px;align-items:baseline;flex-wrap:wrap">
        <${SeverityChip} severity=${theme.severity} />
        <span style="font-weight:600;flex:1;min-width:220px">
          ${theme.sentence}</span>
        <button class="btn btn-sm no-print"
          onClick=${() => onNavigate('findings')}>Detail</button>
      </div>
      ${theme.remediation && html`<div class="muted"
        style="font-size:12px;margin-top:3px">${theme.remediation}</div>`}
      ${theme.confidence_note && html`<div class="subtle"
        style="font-size:11px;margin-top:2px">${theme.confidence_note}</div>`}
    </div>`)}
  </div>`;
}

// ── Where the work is ───────────────────────────────────────────────────────

function Where({ byZone, byEnv }) {
  const zones = (byZone || []).filter((z) => z.hosts > 0).slice(0, 10);
  const envs = (byEnv || []).filter((e) => e.hosts > 0);

  return html`<div class="card no-print-break">
    <${CardTitle} topic="exec.narrative">Where the work is<//>
    <div style="display:grid;gap:20px;
                grid-template-columns:repeat(auto-fit,minmax(320px,1fr))">
      <div>
        <div class="kpi-label" style="margin-bottom:8px">
          By zone — hosts, and how many need attention</div>
        <${GroupedBars} rows=${zones} labelKey="dimension"
          series=${[
            { key: 'hosts', label: 'Hosts', colour: seriesColour(0) },
            { key: 'needs_attention', label: 'Needing attention',
              colour: 'var(--status-critical)' },
          ]} />
      </div>
      <div>
        <div class="kpi-label" style="margin-bottom:8px">
          By environment</div>
        <${GroupedBars} rows=${envs} labelKey="dimension"
          series=${[
            { key: 'hosts', label: 'Hosts', colour: seriesColour(0) },
            { key: 'needs_attention', label: 'Needing attention',
              colour: 'var(--status-critical)' },
          ]} />
      </div>
    </div>
  </div>`;
}

// ── Top hosts ───────────────────────────────────────────────────────────────

function TopHosts({ hosts, onNavigate }) {
  if (!hosts || !hosts.length) return null;
  return html`<div class="card no-print-break">
    <h3>Highest-risk hosts</h3>
    <div class="scroll-x"><table class="plain">
      <thead><tr>
        <th>Host</th><th>Worst issue</th><th>What it is</th>
        <th class="right">Score</th><th class="right">Findings</th>
        <th>Environment</th>
      </tr></thead>
      <tbody>
        ${hosts.map((host) => html`<tr>
          <td><a href="#" class="mono" onClick=${(e) => {
            e.preventDefault();
            onNavigate('endpoints', { filters: { host: [host.host] } });
          }}>${host.host_display || host.host}</a></td>
          <td>${host.worst_severity
            ? html`<${SeverityChip} severity=${host.worst_severity} />`
            : html`<span class="subtle">—</span>`}</td>
          <td>${host.worst_finding ? host.worst_finding.title : ''}
            ${host.other_findings.length ? html`<div class="subtle"
              style="font-size:11px">+ ${host.other_findings.join(', ')}</div>` : null}</td>
          <td class="num right">${host.risk_score}</td>
          <td class="num right">${host.finding_count}</td>
          <td>${host.env}</td>
        </tr>`)}
      </tbody>
    </table></div>
  </div>`;
}

// ── End of life ─────────────────────────────────────────────────────────────

function Eol({ eol }) {
  return html`<div class="card no-print-break">
    <h3>Software past end of life</h3>
    <p style="margin-top:0" class="muted">
      Software the vendor no longer patches. No configuration change makes these
      safe; they need upgrading or removing from the internet.
    </p>
    <${RankedBars} rows=${eol.products} labelKey="name" valueKey="hosts"
      colour=${(row) => SEVERITY_TOKEN[row.severity] || SEVERITY_TOKEN.high}
      unit=" hosts" />
    <${Legend} items=${[...new Set(eol.products.map((p) => p.severity))]
      .map((severity) => ({
        label: `${severity[0].toUpperCase()}${severity.slice(1)}`,
        colour: SEVERITY_TOKEN[severity] || SEVERITY_TOKEN.high,
      }))} />
    <div class="scroll-x" style="margin-top:10px"><table class="plain">
      <thead><tr><th>Product</th><th>Unsupported since</th>
        <th class="right">Years</th><th class="right">Hosts</th></tr></thead>
      <tbody>${eol.products.map((p) => html`<tr>
        <td>${p.name}</td>
        <td>${p.eol_date || html`<span class="subtle">no published date</span>`}</td>
        <td class="num right">${p.years_past_eol
          ? Math.round(p.years_past_eol) : '—'}</td>
        <td class="num right">${p.hosts}</td>
      </tr>`)}</tbody>
    </table></div>
  </div>`;
}

// ── Comparison placeholder ──────────────────────────────────────────────────

function Comparison({ comparison, trends, onNavigate }) {
  const enough = trends && trends.enough_runs;
  if (!enough) {
    // Stated rather than drawn as an empty chart: a flat line reads as "no
    // change" when the truth is "no data".
    return html`<div class="card no-print-break">
      <h3>Change over time</h3>
      <div class="banner info" style="margin-bottom:0">
        <span>◌</span>
        <div><strong>Not available yet.</strong> ${comparison.reason}
        Ingest a second scan and this page will show what appeared, what was
        fixed, and the direction of travel.
        <div class="no-print" style="margin-top:8px">
          <button class="btn btn-sm" onClick=${() => onNavigate('runs')}>
            Upload another scan</button>
        </div></div>
      </div>
    </div>`;
  }

  const headline = ['hosts_needing_attention', 'findings_critical',
                    'findings_total', 'no_waf_hosts', 'posture_index_host'];
  return html`<div class="card no-print-break">
    <h3>Change over time</h3>
    <div class="muted" style="margin-top:0;font-size:12px">
      Across ${trends.runs.length} scans.
    </div>
    <div class="grid-cards" style="margin-top:10px">
      ${headline.filter((m) => trends.metrics[m]).map((metric) => {
        const entry = trends.metrics[metric];
        const values = entry.points.map((p) => p.value);
        const last = values[values.length - 1];
        return html`<div class="card kpi">
          <div style="display:flex;align-items:baseline;gap:8px">
            <span class="kpi-value" style="font-size:20px">${
              Number.isInteger(last) ? num(last) : last.toFixed(1)}</span>
            <${TrendDelta} trends=${trends} metric=${metric} />
          </div>
          <div class="kpi-label">${entry.label}</div>
          <${Sparkline} points=${values} width=${110} height=${24}
            colour=${HIGHER_IS_BETTER.has(metric)
              ? 'var(--status-good)' : seriesColour(0)} />
        </div>`;
      })}
    </div>
    <div class="no-print" style="margin-top:10px">
      <button class="btn btn-sm" onClick=${() => onNavigate('changes')}>
        What changed</button>
      <button class="btn btn-sm" onClick=${() => onNavigate('trends')}>
        All trends</button>
    </div>
  </div>`;
}

// ── Caveats ─────────────────────────────────────────────────────────────────

function Caveats({ caveats, onNavigate }) {
  return html`<div class="card no-print-break">
    <h3>What this scan could not see</h3>
    <ul style="margin:0;padding-left:18px">
      ${caveats.map((caveat) => html`<li style="margin-bottom:4px">${caveat}</li>`)}
    </ul>
    <div class="no-print" style="margin-top:10px;display:flex;gap:8px;flex-wrap:wrap">
      <button class="btn btn-sm" onClick=${() => onNavigate('coverage')}>
        Coverage detail</button>
      <button class="btn btn-sm" onClick=${() => onNavigate('methodology')}>
        How scoring works</button>
    </div>
  </div>`;
}
