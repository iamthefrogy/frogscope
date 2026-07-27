// Inventory views: Takeover, Technology, Infrastructure, Auth surfaces.
//
// All counts are per HOST. A Cloudflare-fronted host contributes a dozen
// near-identical endpoints, so endpoint counts in an inventory overstate every
// total several-fold — "1,785 endpoints run Cloudflare" is true and useless.

import { h } from 'preact';
import { useEffect, useMemo, useState } from 'preact/hooks';
import htm from 'htm';
import { Legend, RankedBars, SEVERITY_TOKEN, seriesColour } from './charts.js';
import { num, responseClassMeta, titleCase, truncate } from './lib.js';
import { SeverityChip } from './risk.js';
import { CardTitle } from './help.js';
import { store } from './store.js';

const html = htm.bind(h);

function useInventory(kind, run, project) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  useEffect(() => {
    setData(null);
    setError(null);
    // Goes through store.js like every other view now — this used to call
    // fetch() directly, which left a hole in the offline single-file export
    // (SNAP mode had no branch for these three views at all).
    store.inventory(kind, run, project)
      .then((d) => (d.error ? setError(d.error) : setData(d)))
      .catch((e) => setError(e.message));
  }, [kind, run, project]);
  return [data, error];
}

function Empty({ title, note }) {
  return html`<div class="view-scroll"><div class="empty">
    <h2>${title}</h2><p class="muted">${note}</p></div></div>`;
}

// ── Takeover candidates ─────────────────────────────────────────────────────

const GRADE_SEVERITY = { high: 'critical', medium: 'high', low: 'medium' };

export function TakeoverView({ run, project, onNavigate }) {
  const [data, error] = useInventory('takeover', run, project);
  const [expanded, setExpanded] = useState({});

  if (error) return html`<${Empty} title="Nothing to show" note=${error} />`;
  if (!data) return html`<div class="loading">Loading…</div>`;

  if (!data.candidates.length && !data.broken_origins.length) {
    return html`<${Empty} title="No takeover candidates"
      note="No hostname in this scan shows a dangling-delegation pattern." />`;
  }

  return html`<div class="view-scroll">
    <div class="banner info">
      <span>i</span>
      <div><strong>These are candidates, not confirmed takeovers.</strong>${' '}
      ${data.verify_note || 'Ingest makes no network requests, so the strongest '
        + 'grade reachable from scan data alone is "likely dangling". Confirming '
        + 'one needs a live DNS and provider check.'}</div>
    </div>

    <div class="grid-cards" style="margin-bottom:14px">
      ${Object.entries(data.by_grade).map(([grade, count]) => html`
        <div class="card kpi">
          <div class="kpi-value" style=${
            `color:${SEVERITY_TOKEN[GRADE_SEVERITY[grade]] || 'inherit'}`}>
            ${num(count)}</div>
          <div class="kpi-label">${titleCase(grade)} confidence</div>
        </div>`)}
      <div class="card kpi">
        <div class="kpi-value">${num(data.totals.broken_origin_hosts)}</div>
        <div class="kpi-label">Broken origins</div>
        <div class="kpi-note">Reachable but misconfigured — not a takeover.</div>
      </div>
    </div>

    <div class="card">
      <h3>Candidates (${data.candidates.length})</h3>
      ${data.candidates.map((c) => {
        const open = expanded[c.host];
        return html`<div class="exec-theme">
          <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;
                      cursor:pointer"
               onClick=${() => setExpanded({ ...expanded, [c.host]: !open })}>
            <${SeverityChip} severity=${GRADE_SEVERITY[c.grade] || 'info'} />
            <span class="chip">${c.grade_label || c.grade}</span>
            <span class="chip">${titleCase(c.confidence || '')} confidence</span>
            <code style="flex:1;min-width:200px">${c.host_display || c.host}</code>
            <span class="subtle">${c.provider}</span>
            <span class="subtle">${open ? '▾' : '▸'}</span>
          </div>
          ${open && html`<div style="margin-top:8px">
            ${c.grade_description && html`<p class="muted"
              style="margin:0 0 8px">${c.grade_description}</p>`}
            <dl class="kv">
              <dt>Status</dt><dd>${c.status_code}
                ${c.cf_error_code ? html` <span class="muted">
                  (Cloudflare error ${c.cf_error_code})</span>` : ''}</dd>
              <dt>Origin health</dt><dd>${titleCase(c.origin_health || '')}</dd>
              <dt>CNAME chain</dt>
              <dd>${(c.cname || []).length
                ? c.cname.map((x, i) => html`<div>
                    <span class="subtle">${i ? '↳ ' : ''}</span><code>${x}</code>
                  </div>`)
                : html`<span class="subtle">none</span>`}</dd>
              <dt>Affected ports</dt><dd>${c.endpoints.length}</dd>
            </dl>

            ${(c.evidence || []).length ? html`<div style="margin-top:8px">
              <div class="kpi-label" style="margin-bottom:4px">Evidence</div>
              <table class="plain"><tbody>
                ${c.evidence.map((e) => html`<tr>
                  <td style="width:150px">${e.test}</td>
                  <td>${e.observed}</td>
                  <td style="width:130px"><span class="chip">${e.verdict}</span></td>
                </tr>`)}
              </tbody></table>
            </div>` : null}

            <div style="margin-top:8px">
              <div class="kpi-label" style="margin-bottom:4px">
                How to confirm this yourself</div>
              <pre style="background:var(--color-bg);padding:8px;
                          border-radius:var(--radius-sm);overflow-x:auto;
                          font-size:12px;margin:0">${
                (c.verify_commands || []).join('\n')}</pre>
              <button class="btn btn-sm" style="margin-top:6px"
                onClick=${(e) => { e.stopPropagation();
                  navigator.clipboard.writeText((c.verify_commands || []).join('\n')); }}>
                Copy commands</button>
              <button class="btn btn-sm" style="margin-top:6px"
                onClick=${(e) => { e.stopPropagation();
                  onNavigate('exec', { filters: { host: [c.host] } }); }}>
                Open in the grid</button>
            </div>
          </div>`}
        </div>`;
      })}
    </div>

    ${data.broken_origins.length ? html`<div class="card">
      <h3>Broken origins (${data.broken_origins.length})</h3>
      <p class="muted" style="margin-top:0">
        The edge reaches these hostnames but cannot get a usable response from the
        server behind them. Kept separate from the candidates above on purpose: a
        525 means the origin answers and its TLS is broken, which is an
        availability bug rather than a dangling record. Conflating the two is how
        a takeover feed loses credibility.
      </p>
      <div class="scroll-x"><table class="plain">
        <thead><tr><th>Host</th><th>Health</th><th class="right">Status</th>
          <th class="right">CF error</th></tr></thead>
        <tbody>${data.broken_origins.map((b) => html`<tr>
          <td class="mono">${b.host_display || b.host}</td>
          <td>${titleCase(b.origin_health || '')}</td>
          <td class="num right">${b.status_code}</td>
          <td class="num right">${b.cf_error_code || '—'}</td>
        </tr>`)}</tbody>
      </table></div>
    </div>` : null}
  </div>`;
}

// ── Technology and lifecycle ────────────────────────────────────────────────

export function TechnologyView({ run, project, onNavigate }) {
  const [data, error] = useInventory('technology', run, project);
  const [search, setSearch] = useState('');

  if (error) return html`<${Empty} title="Nothing to show" note=${error} />`;
  if (!data) return html`<div class="loading">Loading…</div>`;

  const needle = search.toLowerCase();
  const tech = data.tech.filter((t) => !needle || t.name.toLowerCase().includes(needle));

  return html`<div class="view">
    <div class="toolbar">
      <input class="input" style="min-width:240px" placeholder="Find a technology…"
        value=${search} onInput=${(e) => setSearch(e.target.value)} />
      <span class="muted">${num(data.totals.distinct_tech)} distinct ·
        ${num(data.webservers.length)} web servers ·
        ${num(data.totals.eol_hosts)} hosts with end-of-life software</span>
    </div>
    <div class="view-scroll">
      ${data.eol.length ? html`<div class="card">
        <h3>End of life (${data.eol.length} products,
          ${num(data.totals.eol_hosts)} hosts)</h3>
        <p class="muted" style="margin-top:0">
          The vendor no longer issues security patches. No configuration change
          makes these safe — they need upgrading, or removing from the internet.
        </p>
        <div class="scroll-x"><table class="plain">
          <thead><tr><th>Product</th><th>Unsupported since</th>
            <th class="right">Years</th><th class="right">Hosts</th>
            <th>Severity</th><th>Note</th></tr></thead>
          <tbody>${data.eol.map((e) => html`<tr>
            <td>${e.name}</td>
            <td>${e.eol_date || html`<span class="subtle">no published date</span>`}</td>
            <td class="num right">${e.years_past_eol
              ? Math.round(e.years_past_eol) : '—'}</td>
            <td class="num right">${e.hosts}</td>
            <td><${SeverityChip} severity=${e.severity} /></td>
            <td class="subtle" style="max-width:320px">${e.note}</td>
          </tr>`)}</tbody>
        </table></div>
      </div>` : null}

      ${data.inconsistent_versions.length ? html`<div class="card">
        <h3>Inconsistent versions (${data.inconsistent_versions.length})</h3>
        <p class="muted" style="margin-top:0">
          The same product at more than one version across the estate. A single
          "outdated" flag hides this, but it is usually the more useful signal —
          it means patching is not reaching everywhere.
        </p>
        <div class="scroll-x"><table class="plain">
          <thead><tr><th>Product</th><th class="right">Versions</th>
            <th>Spread</th><th class="right">Hosts</th></tr></thead>
          <tbody>${data.inconsistent_versions.map((t) => html`<tr>
            <td>${t.name}</td>
            <td class="num right">${t.version_count}</td>
            <td><span class="chip-list">${Object.entries(t.by_version).map(
              ([v, n]) => html`<span class="chip">${v} <strong>${n}</strong></span>`)}
            </span></td>
            <td class="num right">${t.hosts}</td>
          </tr>`)}</tbody>
        </table></div>
      </div>` : null}

      ${data.outdated.length ? html`<div class="card">
        <h3>Behind the minimum safe version (${data.outdated.length})</h3>
        <div class="scroll-x"><table class="plain">
          <thead><tr><th>Component</th><th>Found</th><th>Minimum safe</th>
            <th class="right">Hosts</th></tr></thead>
          <tbody>${data.outdated.map((o) => html`<tr>
            <td>${o.name}</td>
            <td>${o.versions.join(', ')}</td>
            <td>${o.min_safe}</td>
            <td class="num right">${o.hosts}</td>
          </tr>`)}</tbody>
        </table></div>
      </div>` : null}

      <div class="card">
        <${CardTitle} topic="inventory.technology">Detected technologies (${tech.length})<//>
        ${data.tech.length === 0 ? html`<p class="subtle" style="margin:0">
          No technology recognised in this scan. This comes from httpx's own
          built-in signature set — solid for common CMS platforms and JS
          frameworks, but it will show nothing for a custom or internal app it
          doesn't recognise. That's expected, not a broken scan: check
          <strong>Assets → Application</strong> for panel/product fingerprints,
          which are Frogscope's own — broader, and tunable in
          <code>config/fingerprints.yaml</code>.</p>` : html`
          <${RankedBars} rows=${tech.slice(0, 25)} labelKey="name" valueKey="hosts"
            unit=" hosts" />
          ${tech.length > 25 && html`<p class="subtle" style="margin-top:8px">
            Showing the 25 most widespread. Use the search box to find others.</p>`}`}
      </div>

      <div class="card">
        <h3>Web servers</h3>
        <${RankedBars} rows=${data.webservers.slice(0, 12)} labelKey="name"
          valueKey="hosts" unit=" hosts" colour=${seriesColour(2)} />
      </div>

      ${data.wordpress_plugins.length ? html`<div class="card">
        <h3>WordPress plugins (${num(data.totals.wordpress_hosts)} hosts)</h3>
        <${RankedBars} rows=${data.wordpress_plugins.slice(0, 15)} labelKey="name"
          valueKey="hosts" unit=" hosts" colour=${seriesColour(4)} />
      </div>` : null}
    </div>
  </div>`;
}

// ── Infrastructure ──────────────────────────────────────────────────────────

export function InfraView({ run, project, onNavigate }) {
  const [data, error] = useInventory('infrastructure', run, project);
  const [gridLimit, setGridLimit] = useState(40);
  const [hostFilter, setHostFilter] = useState('');

  if (error) return html`<${Empty} title="Nothing to show" note=${error} />`;
  if (!data) return html`<div class="loading">Loading…</div>`;

  const needle = hostFilter.toLowerCase();
  const grid = data.grid.filter((g) => !needle || g.host.includes(needle));

  return html`<div class="view-scroll">
    <div class="grid-cards" style="margin-bottom:14px">
      <div class="card kpi">
        <div class="kpi-value">${num(data.address_total)}</div>
        <div class="kpi-label">Distinct addresses</div>
      </div>
      <div class="card kpi">
        <div class="kpi-value">${num(data.providers.length)}</div>
        <div class="kpi-label">Hosting providers</div>
      </div>
      <div class="card kpi">
        <div class="kpi-value">${num(data.ipv6_hosts)}</div>
        <div class="kpi-label">Hosts with IPv6</div>
      </div>
      <div class="card kpi">
        <div class="kpi-value">${num(data.ports.length)}</div>
        <div class="kpi-label">Ports probed</div>
      </div>
    </div>

    ${!data.ownership_configured && data.ownership_note ? html`
      <div class="banner info">
        <span>i</span><div>${data.ownership_note}</div>
      </div>` : null}

    <div class="card">
      <h3>Ports: what is a service and what is not</h3>
      <p class="muted" style="margin-top:0">
        On a Cloudflare-fronted host most ports are proxy aliases of the same
        origin site, and a TLS-only port probed over cleartext returns a 400 that
        is the server behaving correctly. The three categories are mutually
        exclusive and add up to the probed count.
      </p>
      <div class="scroll-x"><table class="plain">
        <thead><tr><th class="right">Port</th><th class="right">Probed</th>
          <th class="right">Real services</th><th class="right">CF aliases</th>
          <th class="right">Scan artefacts</th><th class="right">Serving</th>
        </tr></thead>
        <tbody>${data.port_rows.map((p) => html`<tr>
          <td class="num right"><a href="#" onClick=${(e) => {
            e.preventDefault();
            onNavigate('exec', { filters: { port: [String(p.port)] } });
          }}>${p.port}</a></td>
          <td class="num right">${num(p.total)}</td>
          <td class="num right" style=${p.real
            ? 'font-weight:600' : 'color:var(--color-text-subtle)'}>${num(p.real)}</td>
          <td class="num right subtle">${num(p.aliases)}</td>
          <td class="num right subtle">${num(p.artefacts)}</td>
          <td class="num right">${num(p.serving)}</td>
        </tr>`)}</tbody>
      </table></div>
    </div>

    <div class="card">
      <h3>Host by port</h3>
      <p class="muted" style="margin-top:0">
        One row per host, one column per probed port. Ordered by how much
        genuinely distinct surface each host has.
      </p>
      <div style="display:flex;gap:8px;align-items:center;margin-bottom:8px;
                  flex-wrap:wrap">
        <input class="input" placeholder="Filter hosts…" value=${hostFilter}
          onInput=${(e) => setHostFilter(e.target.value)} />
        <select class="input" value=${String(gridLimit)}
          onChange=${(e) => setGridLimit(Number(e.target.value))}>
          ${[20, 40, 80, 200].map((n) => html`<option value=${n}>${n} hosts</option>`)}
        </select>
        <span class="muted">${grid.length} of ${data.grid_total} hosts</span>
      </div>
      <div class="scroll-x">
        <table class="plain" style="font-size:11px">
          <thead><tr>
            <th style="min-width:200px">Host</th>
            ${data.ports.map((p) => html`<th class="right"
              style="writing-mode:vertical-rl;height:52px">${p}</th>`)}
            <th class="right">Real</th>
          </tr></thead>
          <tbody>
            ${grid.slice(0, gridLimit).map((row) => html`<tr>
              <td class="mono"><a href="#" onClick=${(e) => {
                e.preventDefault();
                onNavigate('exec', { filters: { host: [row.host] } });
              }}>${truncate(row.host_display || row.host, 34)}</a></td>
              ${data.ports.map((port) => {
                const cell = row.cells[String(port)];
                if (!cell) {
                  return html`<td style="text-align:center;color:var(--color-border)"
                    title="not probed or no response">·</td>`;
                }
                const meta = responseClassMeta(cell.response_class);
                const dim = cell.alias || cell.artefact;
                const colour = cell.artefact ? 'var(--color-text-subtle)'
                  : cell.alias ? seriesColour(3)
                  : meta.state === 'bad' ? 'var(--status-critical)'
                  : meta.state === 'warn' ? 'var(--status-medium)'
                  : meta.state === 'good' ? 'var(--status-good)'
                  : seriesColour(0);
                return html`<td style=${`text-align:center;color:${colour};`
                  + `opacity:${dim ? 0.5 : 1}`}
                  title=${`:${port} — ${meta.label}`
                    + (cell.alias ? ' (Cloudflare alias)' : '')
                    + (cell.artefact ? ' (scan artefact)' : '')}>
                  ${cell.artefact ? '∅' : cell.alias ? '◌' : '■'}</td>`;
              })}
              <td class="num right">${row.real_ports}</td>
            </tr>`)}
          </tbody>
        </table>
      </div>
      <${Legend} items=${[
        { label: 'Real service', colour: seriesColour(0) },
        { label: 'Cloudflare alias (◌)', colour: seriesColour(3) },
        { label: 'Scan artefact (∅)', colour: 'var(--color-text-subtle)' },
        { label: 'No response (·)', colour: 'var(--color-border)' },
      ]} />
    </div>

    <div style="display:grid;gap:12px;
                grid-template-columns:repeat(auto-fit,minmax(320px,1fr))">
      <div class="card">
        <${CardTitle} topic="inventory.infra">Blast radius by address<//>
        <p class="muted" style="margin-top:0">
          How many hostnames each address serves. Anything affecting the top entry
          affects all of them at once.
        </p>
        <${RankedBars} rows=${data.addresses.slice(0, 15)} labelKey="ip"
          valueKey="hosts" unit=" hosts" colour=${(row) =>
            (row.hosts >= 50 ? 'var(--status-critical)'
              : row.hosts >= 20 ? 'var(--status-medium)' : seriesColour(0))} />
      </div>
      <div class="card">
        <${CardTitle} topic="inventory.infra">Supply chain<//>
        <p class="muted" style="margin-top:0">
          Every provider traffic passes through, from the CNAME chain — not just
          the outermost one.
        </p>
        <${RankedBars} rows=${data.supply_chain.slice(0, 15)} labelKey="name"
          valueKey="hosts" unit=" hosts" colour=${seriesColour(2)} />
      </div>
      <div class="card">
        <h3>Origin providers</h3>
        <${RankedBars} rows=${data.providers.slice(0, 12)} labelKey="name"
          valueKey="hosts" unit=" hosts" colour=${seriesColour(1)} />
      </div>
      <div class="card">
        <${CardTitle} topic="inventory.takeover">Delegation targets<//>
        <${RankedBars} rows=${data.cname_apex.slice(0, 12)} labelKey="apex"
          valueKey="hosts" unit=" hosts" colour=${seriesColour(6)} />
      </div>
    </div>
  </div>`;
}

// ── Auth surfaces ───────────────────────────────────────────────────────────

export function AuthView({ run, project, onNavigate }) {
  const [data, error] = useInventory('auth', run, project);
  const [expanded, setExpanded] = useState({});

  if (error) return html`<${Empty} title="Nothing to show" note=${error} />`;
  if (!data) return html`<div class="loading">Loading…</div>`;

  if (!data.groups.length) {
    return html`<${Empty} title="No authentication surfaces found"
      note="No login, admin, or remote-access portal was detected in this scan." />`;
  }

  const t = data.totals;

  return html`<div class="view-scroll">
    <div class="grid-cards" style="margin-bottom:14px">
      <div class="card kpi">
        <div class="kpi-value">${num(t.hosts)}</div>
        <div class="kpi-label">Hosts with a login surface</div>
      </div>
      <div class="card kpi">
        <div class="kpi-value" style="color:var(--status-good)">${num(t.federated)}</div>
        <div class="kpi-label">Federated endpoints</div>
        <div class="kpi-note">Delegated to an identity provider — no credentials
          handled here. This is the good case.</div>
      </div>
      <div class="card kpi">
        <div class="kpi-value">${num(t.local)}</div>
        <div class="kpi-label">Handling credentials locally</div>
        <div class="kpi-note">Where a weak login actually matters.</div>
      </div>
      <div class="card kpi">
        <div class="kpi-value">${num(t.remote_access_hosts)}</div>
        <div class="kpi-label">Remote-access portals</div>
        <div class="kpi-note">VPN, Citrix, and remote-desktop gateways.</div>
      </div>
    </div>

    ${data.over_http.length ? html`<div class="banner">
      <span>▲</span>
      <div><strong>${`${data.over_http.length} login surface(s) served over `
        + `plain HTTP.`}</strong>${' '}Credentials submitted there cross the
      network in clear text.
      <div class="chip-list" style="margin-top:6px">
        ${data.over_http.slice(0, 12).map((e) => html`
          <span class="chip" data-state="bad">${e.host}</span>`)}
      </div></div>
    </div>` : null}

    <div class="card">
      <h3>By type</h3>
      ${data.groups.map((g) => {
        const open = expanded[g.type];
        return html`<div class="exec-theme">
          <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;
                      cursor:pointer"
               onClick=${() => setExpanded({ ...expanded, [g.type]: !open })}>
            <strong style="flex:1;min-width:160px">${titleCase(g.type)}</strong>
            <span class="chip">${g.hosts} host${g.hosts === 1 ? '' : 's'}</span>
            ${g.federated > 0 && html`<span class="chip" data-state="good">
              ✓ ${g.federated} federated</span>`}
            ${g.local > 0 && html`<span class="chip">${g.local} local</span>`}
            ${g.no_waf > 0 && html`<span class="chip" data-state="warn">
              ▲ ${g.no_waf} without a WAF</span>`}
            ${g.over_http > 0 && html`<span class="chip" data-state="bad">
              ▲ ${g.over_http} over HTTP</span>`}
            <span class="subtle">${open ? '▾' : '▸'}</span>
          </div>
          ${open && html`<div class="scroll-x" style="margin-top:8px">
            <table class="plain">
              <thead><tr><th>Endpoint</th><th>Risk</th><th>Federated</th>
                <th>Identity provider</th><th>Env</th><th>Title</th></tr></thead>
              <tbody>${g.endpoints.slice(0, 60).map((e) => html`<tr>
                <td class="mono"><a href="#" onClick=${(ev) => {
                  ev.preventDefault();
                  onNavigate('exec', { filters: { host: [e.host] } });
                }}>${e.endpoint_key}</a></td>
                <td>${e.risk_band
                  ? html`<${SeverityChip} severity=${e.risk_band} />` : '—'}</td>
                <td>${e.federated
                  ? html`<span class="chip" data-state="good">✓ yes</span>`
                  : html`<span class="subtle">no</span>`}</td>
                <td class="subtle">${truncate(e.idp || '', 34)}</td>
                <td>${e.env}</td>
                <td>${truncate(e.title || '', 40)}</td>
              </tr>`)}</tbody>
            </table>
            ${g.endpoint_count > 60 && html`<p class="subtle">
              Showing 60 of ${g.endpoint_count}.</p>`}
          </div>`}
        </div>`;
      })}
    </div>

    ${data.remote_access.length ? html`<div class="card">
      <h3>Remote-access appliances (${data.remote_access.length})</h3>
      <p class="muted" style="margin-top:0">
        These are necessarily public, and they are also the most heavily targeted
        appliances in any estate. Worth confirming each is on a current build with
        multi-factor authentication enforced.
      </p>
      <div class="scroll-x"><table class="plain">
        <thead><tr><th>Host</th><th>Type</th><th>Risk</th>
          <th>Product fingerprint</th></tr></thead>
        <tbody>${data.remote_access.map((e) => html`<tr>
          <td class="mono">${e.host_display || e.host}</td>
          <td>${titleCase(e.type)}</td>
          <td>${e.risk_band
            ? html`<${SeverityChip} severity=${e.risk_band} />` : '—'}</td>
          <td><span class="chip-list">${(e.cpe || []).map(
            (c) => html`<span class="chip">${c}</span>`)}</span></td>
        </tr>`)}</tbody>
      </table></div>
    </div>` : null}

    ${data.management.length ? html`<div class="card">
      <h3>Management consoles (${data.management.length})</h3>
      <div class="scroll-x"><table class="plain">
        <thead><tr><th>Host</th><th>Risk</th><th>Auth detected</th>
          <th>Title</th></tr></thead>
        <tbody>${data.management.map((e) => html`<tr>
          <td class="mono">${e.host_display || e.host}</td>
          <td>${e.risk_band
            ? html`<${SeverityChip} severity=${e.risk_band} />` : '—'}</td>
          <td>${e.type === 'none'
            ? html`<span class="chip" data-state="warn">▲ none detected</span>`
            : titleCase(e.type)}</td>
          <td>${truncate(e.title || '', 44)}</td>
        </tr>`)}</tbody>
      </table></div>
      <p class="kpi-note" style="margin-bottom:0">
        "None detected" means an unauthenticated probe saw no login. It cannot
        rule one out — that needs response-body inspection, which this scan did
        not collect.
      </p>
    </div>` : null}
  </div>`;
}
