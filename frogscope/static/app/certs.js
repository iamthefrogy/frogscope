// Certificate inventory (v2), from tlsx — empty until a scan opts into
// "Correlate assets". Sorted by days-to-expiry ascending: opens on the
// thing that breaks first.

import { h } from 'preact';
import { useEffect, useState } from 'preact/hooks';
import htm from 'htm';
import { store } from './store.js';
import { num, when } from './lib.js';
import { CardTitle } from './help.js';

const html = htm.bind(h);

const STATUS_FILTERS = [
  ['', 'All'], ['broken', 'Broken'], ['expired', 'Expired'],
  ['self_signed', 'Self-signed'], ['mismatched', 'Mismatched'],
];

function Empty({ title, note }) {
  return html`<div class="view-scroll"><div class="empty">
    <h2>${title}</h2><p class="muted">${note}</p>
  </div></div>`;
}

function expiryChip(cert) {
  if (cert.expired) return html`<span class="chip" data-state="bad">expired</span>`;
  if (cert.days_remaining === null || cert.days_remaining === undefined) return null;
  if (cert.days_remaining <= 30) {
    return html`<span class="chip" data-state="warn">${cert.days_remaining}d left</span>`;
  }
  return html`<span class="chip" data-state="good">${cert.days_remaining}d left</span>`;
}

export function CertificatesView({ run, project, onNavigate }) {
  const [status, setStatus] = useState('');
  const [data, setData] = useState(null);
  const [selected, setSelected] = useState(null);
  const [detail, setDetail] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    setData(null); setError(null);
    store.certs(run, project, { status, page_size: 200 })
      .then(setData).catch((e) => setError(e.message));
  }, [run, project, status]);

  useEffect(() => {
    if (!selected) { setDetail(null); return; }
    store.cert(selected, run, project).then(setDetail).catch(() => setDetail(null));
  }, [selected, run, project]);

  if (error) return html`<${Empty} title="Nothing to show" note=${error} />`;
  if (!data) return html`<div class="loading">Loading…</div>`;

  if (!data.rows.length && !status) {
    return html`<${Empty} title="No certificates yet"
      note="Turn on “Correlate assets” on the scan form — tlsx reads certificate expiry, trust, mismatches, and every other domain a certificate covers." />`;
  }

  return html`<div class="view-scroll">
    <div class="toolbar" style="margin-bottom:12px">
      ${STATUS_FILTERS.map(([value, label]) => html`
        <button class="tab" aria-current=${status === value ? 'page' : null}
          onClick=${() => setStatus(value)}>${label}</button>`)}
    </div>

    <div class="card">
      <${CardTitle} topic="cert.inventory">Certificates<//>
      <div class="scroll-x"><table class="plain">
        <thead><tr><th>Subject</th><th>Issuer</th><th>Expiry</th>
          <th class="right">Hosts</th><th class="right">SANs</th>
          <th>Flags</th></tr></thead>
        <tbody>${data.rows.map((c) => html`<tr
            style="cursor:pointer" onClick=${() => setSelected(c.cert_sha256)}>
          <td>${c.subject_cn || '(no CN)'}</td>
          <td class="subtle">${c.issuer_org || c.issuer_cn || '—'}</td>
          <td>${expiryChip(c)}</td>
          <td class="num right">${num(c.host_count)}</td>
          <td class="num right">${num(c.san_count)}</td>
          <td><span class="chip-list">
            ${c.self_signed ? html`<span class="chip" data-state="bad">self-signed</span>` : null}
            ${c.mismatched ? html`<span class="chip" data-state="bad">mismatched</span>` : null}
            ${c.untrusted ? html`<span class="chip" data-state="warn">untrusted</span>` : null}
            ${c.wildcard ? html`<span class="chip" data-state="info">wildcard</span>` : null}
            ${c.foreign_domain_count > 0
              ? html`<span class="chip" data-state="warn">${c.foreign_domain_count} foreign</span>`
              : null}
          </span></td>
        </tr>`)}</tbody>
      </table></div>
      ${!data.rows.length ? html`<p class="subtle">Nothing matches this filter.</p>` : null}
    </div>

    ${detail ? html`<div class="card" style="margin-top:16px">
      <div style="display:flex;justify-content:space-between;align-items:center">
        <h3 style="margin:0">${detail.certificate.subject_cn || detail.certificate.cert_sha256}</h3>
        <button class="btn btn-sm" onClick=${() => setSelected(null)}>Close</button>
      </div>
      <div class="kv" style="margin-top:10px">
        <dt>Issuer</dt><dd>${detail.certificate.issuer_dn || '—'}</dd>
        <dt>Not before</dt><dd>${when(detail.certificate.not_before)}</dd>
        <dt>Not after</dt><dd>${when(detail.certificate.not_after)}</dd>
        <dt>TLS version / cipher</dt>
        <dd>${detail.certificate.tls_version || '—'} / ${detail.certificate.cipher || '—'}
          (${detail.certificate.cipher_grade || 'unknown'})</dd>
        <dt>Fingerprint (SHA-256)</dt><dd><code>${detail.certificate.cert_sha256}</code></dd>
      </div>

      <h3 style="margin:16px 0 8px">Names on this certificate</h3>
      <div class="chip-list">
        ${detail.names.map((n) => html`<span class="chip"
          data-state=${n.in_scope ? 'good' : 'warn'}
          title=${n.discovered_new ? 'Not seen in any prior scan of this project' : ''}>
          ${n.name}${n.discovered_new ? ' ✦' : ''}
        </span>`)}
      </div>

      <h3 style="margin:16px 0 8px">Presented by</h3>
      <div class="scroll-x"><table class="plain">
        <thead><tr><th>Host</th><th>Address</th><th class="right">Port</th></tr></thead>
        <tbody>${detail.observations.map((o) => html`<tr>
          <td><a href="#" onClick=${(e) => {
            e.preventDefault();
            onNavigate('endpoints', { filters: { host: [o.host] } });
          }}>${o.host}</a></td>
          <td><code>${o.ip || '—'}</code></td>
          <td class="num right">${o.port}</td>
        </tr>`)}</tbody>
      </table></div>
    </div>` : null}
  </div>`;
}
