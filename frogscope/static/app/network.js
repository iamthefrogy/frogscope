// Network view (v2): CIDR blocks and the addresses inside them, correlated
// via dnsx/mapcidr — empty until a scan opts into "Correlate assets".

import { h } from 'preact';
import { useEffect, useState } from 'preact/hooks';
import htm from 'htm';
import { store } from './store.js';
import { num, truncate } from './lib.js';
import { CardTitle } from './help.js';
import { RankedBars } from './charts.js';

const html = htm.bind(h);

function Empty({ title, note }) {
  return html`<div class="view-scroll"><div class="empty">
    <h2>${title}</h2><p class="muted">${note}</p>
  </div></div>`;
}

export function NetworkView({ run, project, onNavigate }) {
  const [summary, setSummary] = useState(null);
  const [ips, setIps] = useState(null);
  const [cidrs, setCidrs] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    setSummary(null); setIps(null); setCidrs(null); setError(null);
    Promise.all([
      store.network(run, project),
      store.networkIps(run, project, 1, 200),
      store.cidrs(run, project, 1, 100),
    ]).then(([s, i, c]) => { setSummary(s); setIps(i); setCidrs(c); })
      .catch((e) => setError(e.message));
  }, [run, project]);

  if (error) return html`<${Empty} title="Nothing to show" note=${error} />`;
  if (!summary) return html`<div class="loading">Loading…</div>`;

  if (!summary.correlated) {
    return html`<${Empty} title="This run wasn't correlated"
      note="Turn on “Correlate assets” on the scan form to see domain→IP→CIDR relationships, reverse DNS, and address blast radius here." />`;
  }

  const foreignRows = (ips.rows || [])
    .filter((r) => r.foreign_domain_count > 0)
    .map((r) => ({ label: r.ip, value: r.foreign_domain_count }))
    .slice(0, 10);

  return html`<div class="view-scroll">
    <div class="grid-cards" style="margin-bottom:16px">
      <div class="card kpi">
        <div class="kpi-label">Addresses seen</div>
        <div class="kpi-value">${num(summary.unique_ips)}</div>
      </div>
      <div class="card kpi">
        <div class="kpi-label">Address blocks</div>
        <div class="kpi-value">${num(summary.unique_cidrs)}</div>
      </div>
      <div class="card kpi">
        <div class="kpi-label">On shared/foreign hosting</div>
        <div class="kpi-value">${num(summary.foreign_shared_ips)}</div>
      </div>
      <div class="card kpi">
        <div class="kpi-label">In an unclaimed cloud range</div>
        <div class="kpi-value">${num(summary.hosts_in_claimable_ranges)}</div>
      </div>
    </div>

    ${foreignRows.length ? html`<div class="card" style="margin-bottom:16px">
      <${CardTitle} topic="network.shared">Most shared addresses<//>
      <p class="subtle" style="margin:0 0 10px">
        Foreign registrable domains sharing this address — a compromise or
        abuse on a neighbour becomes this address's problem too.
      </p>
      <${RankedBars} rows=${foreignRows} unit=" domains" />
    </div>` : null}

    <div class="card" style="margin-bottom:16px">
      <${CardTitle} topic="network.cidrs">Address blocks<//>
      <div class="scroll-x"><table class="plain">
        <thead><tr><th>Block</th><th class="right">Size</th>
          <th class="right">Observed</th><th>Source</th></tr></thead>
        <tbody>${(cidrs.rows || []).map((c) => html`<tr>
          <td><code>${c.cidr}</code></td>
          <td class="num right">${num(c.ip_count)}</td>
          <td class="num right">${num(c.observed_ip_count)}</td>
          <td>${c.was_scan_target
            ? html`<span class="chip" data-state="info">scan target</span>`
            : html`<span class="chip" data-state="neutral">${c.source}</span>`}</td>
        </tr>`)}</tbody>
      </table></div>
      ${!cidrs.rows.length ? html`<p class="subtle">No address blocks yet.</p>` : null}
    </div>

    <div class="card">
      <${CardTitle} topic="network.overview">Addresses<//>
      <div class="scroll-x"><table class="plain">
        <thead><tr><th>Address</th><th>Block</th><th>Reverse DNS</th>
          <th class="right">Our hostnames</th><th class="right">Foreign domains</th>
          <th>Claimable range</th></tr></thead>
        <tbody>${(ips.rows || []).map((r) => html`<tr>
          <td><a href="#" onClick=${(e) => {
            e.preventDefault();
            onNavigate('endpoints', { filters: { host_ip: [r.ip] } });
          }}><code>${r.ip}</code></a></td>
          <td>${r.cidr ? html`<code>${r.cidr}</code>` : '—'}</td>
          <td class="subtle" title=${(r.ptr || []).join(', ')}>
            ${r.ptr_primary ? truncate(r.ptr_primary, 40) : '—'}
          </td>
          <td class="num right">${num(r.hostname_count)}</td>
          <td class="num right">
            ${r.foreign_domain_count > 0
              ? html`<span class="chip" data-state="warn">${r.foreign_domain_count}</span>`
              : '0'}
          </td>
          <td>${r.in_claimable_range
            ? html`<span class="chip" data-state="bad">${r.claimable_provider}</span>`
            : '—'}</td>
        </tr>`)}</tbody>
      </table></div>
      ${!ips.rows.length ? html`<p class="subtle">No addresses yet.</p>` : null}
    </div>
  </div>`;
}
