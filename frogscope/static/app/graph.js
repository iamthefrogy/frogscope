// One-hop asset relationships (v2) — one component for every node kind
// (ip/cidr/cert/host), reading `/api/graph/<kind>/<key>`. A sortable table,
// not an SVG node graph: this data can run into the thousands of edges (a
// wildcard cert, a CDN address), which a force-directed diagram renders as
// an unreadable smear long before a table would run out of room.

import { h } from 'preact';
import { useEffect, useState } from 'preact/hooks';
import htm from 'htm';
import { store } from './store.js';

const html = htm.bind(h);

const REL_LABEL = {
  resolved_from: 'Resolves from', resolves_to: 'Resolves to',
  named_by_ptr: 'Named by reverse DNS', in_range: 'In range',
  contains: 'Contains', presents_cert: 'Presents certificate',
  presented_by: 'Presented by', covers_name: 'Certificate covers',
};

export function RelationPanel({ kind, id, run, project, onNavigate }) {
  const [graph, setGraph] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    setGraph(null); setError(null);
    store.graph(kind, id, run, project).then(setGraph).catch((e) => setError(e.message));
  }, [kind, id, run, project]);

  if (error) return html`<p class="subtle">${error}</p>`;
  if (!graph) return html`<div class="loading">Loading…</div>`;
  if (!graph.edges.length) return html`<p class="subtle">Nothing else relates to this yet.</p>`;

  const groups = {};
  for (const edge of graph.edges) {
    (groups[edge.rel] = groups[edge.rel] || []).push(edge);
  }

  const jump = (edge) => {
    if (!onNavigate) return;
    if (edge.kind === 'host') onNavigate('exec', { filters: { host: [edge.key] } });
    else if (edge.kind === 'ip') onNavigate('exec', { filters: { host_ip: [edge.key] } });
  };

  return html`<div>
    ${Object.entries(groups).map(([rel, edges]) => html`
      <div style="margin-bottom:12px">
        <div class="subtle" style="font-size:11px;text-transform:uppercase;
             letter-spacing:0.06em;margin-bottom:4px">
          ${REL_LABEL[rel] || rel} (${edges.length})
        </div>
        <table class="plain">
          <tbody>${edges.map((edge) => html`<tr>
            <td>${edge.kind === 'host' || edge.kind === 'ip'
              ? html`<a href="#" onClick=${(e) => { e.preventDefault(); jump(edge); }}>
                  ${edge.label}</a>`
              : html`<code>${edge.label}</code>`}</td>
            <td class="subtle">${edge.note || ''}</td>
          </tr>`)}</tbody>
        </table>
      </div>`)}
    ${graph.truncated ? html`<p class="subtle">Showing the first 200 — this
      node has more relationships than fit here.</p>` : null}
  </div>`;
}
