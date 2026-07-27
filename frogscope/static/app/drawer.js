// Row detail drawer.
//
// Every source column is shown on the Raw tab, including the empty ones, so the
// drawer is always the ground truth even when the grid hides a column.

import { h } from 'preact';
import { useEffect, useState } from 'preact/hooks';
import htm from 'htm';
import { store } from './store.js';
import { ScoreTrace, SeverityChip } from './risk.js';
import { EndpointHistory } from './history.js';
import { bytes, ms, originHealthMeta, responseClassMeta, titleCase, when } from './lib.js';

const html = htm.bind(h);

const TABS = [
  ['overview', 'Overview'],
  ['score', 'Why this score'],
  ['dns', 'DNS & edge'],
  ['tech', 'Technology'],
  ['history', 'History'],
  ['related', 'Related'],
  ['raw', 'Raw record'],
];

function Row({ label, children }) {
  if (children === null || children === undefined || children === '') return null;
  return html`<dt>${label}</dt><dd>${children}</dd>`;
}

function Chips({ items }) {
  const list = Array.isArray(items) ? items : [];
  if (!list.length) return html`<span class="subtle">—</span>`;
  return html`<span class="chip-list">
    ${list.map((item) => html`<span class="chip">${String(item)}</span>`)}
  </span>`;
}

export function Drawer({ endpointKey, run, project, onClose }) {
  const [data, setData] = useState(null);
  const [tab, setTab] = useState('overview');
  const [error, setError] = useState(null);

  useEffect(() => {
    setData(null);
    setError(null);
    store.endpoint(endpointKey, run, project)
      .then(setData)
      .catch((e) => setError(e.message));
  }, [endpointKey, run, project]);

  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  const ep = data && data.endpoint;
  const lists = (ep && ep.lists) || {};

  return html`<div class="drawer-backdrop" onClick=${onClose}>
    <div class="drawer" onClick=${(e) => e.stopPropagation()}>
      <div class="drawer-head">
        <span class="drawer-title">${endpointKey}</span>
        <span class="spacer"></span>
        ${ep && html`<a class="btn btn-sm"
          href=${ep.final_url || `${ep.scheme}://${ep.host_display || ep.host}:${ep.port}`}
          target="_blank" rel="noreferrer noopener"
          title=${ep.final_url
            ? 'Opens where this endpoint actually redirects to'
            : 'Opens the host root — no redirect was recorded for this endpoint'}>
          Open ↗</a>`}
        ${ep && html`<button class="btn btn-sm" onClick=${() => copyCurl(ep)}>
          Copy curl</button>`}
        <button class="btn btn-sm" onClick=${onClose}>Close</button>
      </div>

      <div class="drawer-tabs">
        ${TABS.map(([id, label]) => html`
          <button class="tab" aria-current=${tab === id ? 'page' : null}
            onClick=${() => setTab(id)}>${label}</button>`)}
      </div>

      <div class="drawer-body">
        ${error && html`<div class="banner error">${error}</div>`}
        ${!data && !error && html`<div class="loading">Loading…</div>`}
        ${ep && tab === 'overview' && html`<${Overview} ep=${ep} />`}
        ${ep && tab === 'score' && html`<${ScoreTrace}
          endpointKey=${endpointKey} run=${run} project=${project} />`}
        ${ep && tab === 'dns' && html`<${Dns} ep=${ep} lists=${lists} />`}
        ${ep && tab === 'tech' && html`<${Tech} ep=${ep} lists=${lists} />`}
        ${ep && tab === 'history' && html`<${EndpointHistory}
          endpointKey=${endpointKey} run=${run} project=${project} />`}
        ${ep && tab === 'related' && html`<${Related} data=${data} />`}
        ${ep && tab === 'raw' && html`<${Raw} ep=${ep} />`}
      </div>
    </div>
  </div>`;
}

function Overview({ ep }) {
  const rc = responseClassMeta(ep.response_class);
  const oh = originHealthMeta(ep.origin_health);

  return html`<div>
    <div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:14px">
      ${ep.risk_band && !ep.risk_excluded
        && html`<${SeverityChip} severity=${ep.risk_band} />`}
      ${ep.worst_severity && ep.worst_severity !== ep.risk_band
        && html`<span class="chip" title="Worst single issue on this endpoint">
            worst: ${ep.worst_severity}</span>`}
      <span class="chip" data-state=${rc.state}>${rc.glyph} ${rc.label}</span>
      ${ep.origin_health && ep.origin_health !== 'ok'
        && html`<span class="chip" data-state=${oh.state}>${oh.glyph} ${oh.label}</span>`}
      ${ep.origin_exposed
        && html`<span class="chip" data-state="bad">▲ Reached directly</span>`}
      ${ep.no_waf && html`<span class="chip" data-state="bad">▲ No WAF</span>`}
      ${ep.waf_protected && html`<span class="chip" data-state="good">🛡 WAF</span>`}
      ${ep.federated_auth
        && html`<span class="chip" data-state="good">✓ Federated auth</span>`}
      ${ep.mgmt_surface
        && html`<span class="chip" data-state="bad">▲ Management console</span>`}
      ${ep.remote_access_exposed
        && html`<span class="chip" data-state="bad">▲ Remote access</span>`}
      ${ep.azure_app_proxy
        && html`<span class="chip" data-state="info">● Published via App Proxy</span>`}
      ${ep.scan_artifact
        && html`<span class="chip" data-state="neutral">∅ Scan artefact</span>`}
      ${ep.cf_alias_port
        && html`<span class="chip" data-state="neutral">∅ Cloudflare alias port</span>`}
    </div>

    ${ep.scan_artifact ? html`<div class="banner info">
      httpx probed this TLS-only port over cleartext. The 400 response is the
      server behaving correctly, so this row is excluded from every count.
    </div>` : null}

    ${ep.cf_alias_port ? html`<div class="banner info">
      This is one of Cloudflare's proxy alias ports. It serves the same origin
      site as :443 rather than being an additional service, so counting it as
      extra attack surface would inflate the total several-fold.
    </div>` : null}

    ${ep.origin_exposure_reason ? html`<div class="banner">
      ${ep.origin_exposure_reason}
    </div>` : null}

    <dl class="kv">
      <${Row} label="Host">${ep.host_display || ep.host}</Row>
      <${Row} label="Normalised host">
        <code>${ep.host}</code></Row>
      <${Row} label="Port">${ep.port} <span class="muted">
        (${titleCase(ep.port_category || '')})</span></Row>
      <${Row} label="Scheme">${ep.scheme}</Row>
      <${Row} label="Environment">${ep.env}${ep.env_source
        ? html` <span class="muted">— matched on “${ep.env_source}”</span>` : ''}</Row>
      <${Row} label="Zone">${ep.zone}</Row>
      <${Row} label="Status">${ep.status_code}</Row>
      <${Row} label="Title">${ep.title}</Row>
      <${Row} label="Title class">${titleCase(ep.title_class || '')}</Row>
      <${Row} label="Content type">${ep.content_type}</Row>
      <${Row} label="Size">${ep.content_length ? bytes(ep.content_length) : ''}</Row>
      <${Row} label="Words / lines">
        ${ep.words != null ? `${ep.words} / ${ep.lines}` : ''}</Row>
      <${Row} label="Response time">
        ${ep.response_ms != null ? ms(ep.response_ms) : ''}</Row>
      <${Row} label="Risk score">${ep.risk_excluded
        ? html`<span class="subtle">not scored — scan artefact</span>`
        : html`${ep.risk_score}/100 · ${ep.finding_count} finding${
            ep.finding_count === 1 ? '' : 's'}${ep.risk_mitigated
              ? html` <span class="muted">(reduced by a control)</span>` : ''}`}</Row>
      <${Row} label="Top finding">${ep.top_finding}</Row>
      <${Row} label="Defence layers">
        ${ep.defence_layers} of 3 <span class="muted">(WAF / auth / TLS)</span></Row>
      <${Row} label="Auth surface">${titleCase(ep.auth_surface_type || 'none')}</Row>
      <${Row} label="Final URL">${ep.final_url
        ? html`<a href=${ep.final_url} target="_blank"
                  rel="noreferrer noopener">${ep.final_url}</a>` : ''}</Row>
      <${Row} label="Redirect hops">${ep.redirect_chain_len || ''}</Row>
      <${Row} label="Identical peers">${ep.content_cluster_size > 1
        ? html`${ep.content_cluster_size} endpoints return an identical
               status, size, and title` : ''}</Row>
      <${Row} label="Probed at">${when(ep.scanned_at)}</Row>
      <${Row} label="Probes collapsed">${ep.probe_count > 1
        ? html`${ep.probe_count}${ep.intra_run_inconsistent
            ? ' — and they disagreed, see Raw' : ''}` : ''}</Row>
    </dl>
  </div>`;
}

function Dns({ ep, lists }) {
  return html`<dl class="kv">
    <${Row} label="Resolved IP"><code>${ep.host_ip}</code></Row>
    <${Row} label="A records"><${Chips} items=${lists.a} /></Row>
    <${Row} label="AAAA records"><${Chips} items=${lists.aaaa} /></Row>
    <${Row} label="CNAME chain">
      ${(lists.cname || []).length
        ? html`<div>${lists.cname.map((c, i) => html`
            <div><span class="subtle">${i === 0 ? '' : '↳ '}</span><code>${c}</code></div>`)}</div>`
        : html`<span class="subtle">—</span>`}
    </Row>
    <${Row} label="Provider chain"><${Chips} items=${lists.chain_providers} /></Row>
    <${Row} label="Origin provider">${ep.hosting_provider}
      ${ep.hosting_kind ? html` <span class="muted">(${ep.hosting_kind})</span>` : ''}</Row>
    <${Row} label="Edge provider">${ep.edge_provider}
      ${ep.edge_kind ? html` <span class="muted">(${ep.edge_kind})</span>` : ''}</Row>
    <${Row} label="CDN / WAF">${ep.cdn_name}
      ${ep.cdn_type ? html` <span class="muted">(${ep.cdn_type})</span>` : ''}</Row>
    <${Row} label="Cloudflare error">${ep.cf_error_code || ''}</Row>
    <${Row} label="Hosts on this IP">${ep.ip_cluster_size > 1
      ? html`${ep.ip_cluster_size} — anything reaching this address affects them all`
      : ''}</Row>
    <${Row} label="Resolvers used"><${Chips} items=${lists.resolvers} /></Row>
  </dl>`;
}

function Tech({ ep, lists }) {
  const versions = lists.tech_versions || {};
  return html`<div>
    <dl class="kv">
      <${Row} label="Web server">${ep.webserver}</Row>
      <${Row} label="Version disclosed">${ep.version_disclosure
        ? html`<span class="chip" data-state="warn">▲ ${ep.webserver_version}</span>`
        : html`<span class="subtle">no</span>`}</Row>
      <${Row} label="Technologies"><${Chips} items=${lists.tech} /></Row>
      <${Row} label="CPE products"><${Chips} items=${lists.cpe_products} /></Row>
      <${Row} label="WordPress">${ep.is_wordpress ? 'yes' : ''}</Row>
      <${Row} label="WP plugins"><${Chips} items=${lists.wp_plugins} /></Row>
    </dl>
    ${Object.keys(versions).length ? html`<div style="margin-top:14px">
      <h3 style="font-size:12px;color:var(--color-text-muted)">Detected versions</h3>
      <table class="plain"><tbody>
        ${Object.entries(versions).map(([name, version]) => html`
          <tr><td>${name}</td><td><code>${version}</code></td></tr>`)}
      </tbody></table>
    </div>` : null}
    <div class="banner info" style="margin-top:14px">
      Version and CPE data here comes from banner fingerprinting. It indicates
      what is probably running, not what is confirmed vulnerable.
    </div>
  </div>`;
}

function Related({ data }) {
  const sameHost = data.same_host || [];
  const sameIp = data.same_ip || [];
  const network = data.network;
  const cert = data.cert;
  const sameCert = data.same_cert || [];

  return html`<div>
    <h3 style="font-size:12px;color:var(--color-text-muted)">
      Other ports on this host (${sameHost.length})</h3>
    ${sameHost.length ? html`<div class="scroll-x"><table class="plain">
      <thead><tr><th>Port</th><th>Scheme</th><th>Status</th>
        <th>Class</th><th>Title</th></tr></thead>
      <tbody>${sameHost.map((r) => html`<tr>
        <td class="num">${r.port}</td><td>${r.scheme}</td>
        <td class="num">${r.status_code ?? ''}</td>
        <td>${responseClassMeta(r.response_class).label}</td>
        <td>${r.title || ''}</td></tr>`)}</tbody>
    </table></div>` : html`<p class="subtle">None.</p>`}

    <h3 style="font-size:12px;color:var(--color-text-muted);margin-top:18px">
      Other hosts on the same IP (${sameIp.length})</h3>
    ${sameIp.length ? html`<div class="chip-list">
      ${sameIp.map((r) => html`<span class="chip">${r.host}</span>`)}
    </div>` : html`<p class="subtle">None.</p>`}

    ${network ? html`<div>
      <h3 style="font-size:12px;color:var(--color-text-muted);margin-top:18px">
        Network (v2)</h3>
      <dl class="kv">
        <${Row} label="Address block">${network.cidr
          ? html`<code>${network.cidr}</code>` : ''}</Row>
        <${Row} label="Reverse DNS">${network.ptr_primary}</Row>
        <${Row} label="Foreign domains on this address">
          ${network.foreign_domain_count > 0
            ? html`<span class="chip" data-state="warn">${network.foreign_domain_count}</span>`
            : '0'}</Row>
        <${Row} label="Claimable cloud range">${network.in_claimable_range
          ? html`<span class="chip" data-state="bad">${network.claimable_provider}</span>` : ''}</Row>
      </dl>
    </div>` : null}

    ${cert ? html`<div>
      <h3 style="font-size:12px;color:var(--color-text-muted);margin-top:18px">
        Certificate (v2)</h3>
      <dl class="kv">
        <${Row} label="Subject">${cert.subject_cn}</Row>
        <${Row} label="Issuer">${cert.issuer_org || cert.issuer_cn}</Row>
        <${Row} label="Days remaining">${cert.days_remaining}</Row>
        <${Row} label="Flags"><span class="chip-list">
          ${cert.expired ? html`<span class="chip" data-state="bad">expired</span>` : null}
          ${cert.self_signed ? html`<span class="chip" data-state="bad">self-signed</span>` : null}
          ${cert.mismatched ? html`<span class="chip" data-state="bad">mismatched</span>` : null}
          ${cert.untrusted ? html`<span class="chip" data-state="warn">untrusted</span>` : null}
          ${cert.wildcard ? html`<span class="chip" data-state="info">wildcard</span>` : null}
        </span></Row>
      </dl>
      ${sameCert.length ? html`<p class="subtle" style="margin-top:6px">
        Also presented by ${sameCert.length} other endpoint(s):
        ${sameCert.slice(0, 10).map((o) => `${o.host}:${o.port}`).join(', ')}
        ${sameCert.length > 10 ? '…' : ''}
      </p>` : null}
    </div>` : null}
  </div>`;
}

function Raw({ ep }) {
  const raw = ep.raw || {};
  const extra = ep.extra || {};
  const keys = Object.keys(raw).sort();
  const inconsistent = ep.inconsistent_fields || [];

  return html`<div>
    ${inconsistent.length ? html`<div class="banner">
      Repeat probes within this scan disagreed on:
      ${inconsistent.join(', ')}. The latest observation is shown.
    </div>` : null}
    ${Object.keys(extra).length ? html`<div class="banner info">
      This file carried ${Object.keys(extra).length} column(s) frogscope does not
      map yet: ${Object.keys(extra).join(', ')}. They are preserved here.
    </div>` : null}
    <div class="scroll-x"><table class="plain">
      <thead><tr><th>Source column</th><th>Value</th></tr></thead>
      <tbody>
        ${keys.map((key) => html`<tr>
          <td><code>${key}</code></td>
          <td style="overflow-wrap:anywhere">${raw[key] === '' || raw[key] === null
            ? html`<span class="subtle">(empty)</span>`
            : String(raw[key])}</td>
        </tr>`)}
      </tbody>
    </table></div>
  </div>`;
}

function copyCurl(ep) {
  const url = `${ep.scheme}://${ep.host_display || ep.host}:${ep.port}/`;
  navigator.clipboard.writeText(`curl -sSik --max-time 15 '${url}'`);
}
