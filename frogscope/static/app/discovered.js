// Newly discovered assets (v2): names this scan found evidence of but never
// directly enumerated — a certificate's SAN list, or reverse DNS on an
// address. Recorded, never auto-probed — probing a name nobody entered
// would defeat the authorisation checkbox the whole scan form is built
// around, so each row is a candidate for the NEXT scan, added with consent.

import { h } from 'preact';
import { useEffect, useState } from 'preact/hooks';
import htm from 'htm';
import { store } from './store.js';
import { CardTitle } from './help.js';

const html = htm.bind(h);

const PENDING_KEY = 'frogscope.pending_targets';

function queueForNextScan(names) {
  let existing = [];
  try {
    existing = JSON.parse(window.localStorage.getItem(PENDING_KEY) || '[]');
  } catch {
    existing = [];
  }
  const merged = Array.from(new Set([...existing, ...names]));
  try {
    window.localStorage.setItem(PENDING_KEY, JSON.stringify(merged));
  } catch {
    // Nothing to do if storage is unavailable — the button simply won't
    // pre-fill the next scan form, it still requires the user's own action.
  }
}

export function DiscoveredView({ run, project, onNavigate }) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [added, setAdded] = useState(new Set());

  useEffect(() => {
    setData(null); setError(null);
    store.discovered(run, project).then(setData).catch((e) => setError(e.message));
  }, [run, project]);

  if (error) return html`<div class="view-scroll"><div class="empty">
    <h2>Nothing to show</h2><p class="muted">${error}</p>
  </div></div>`;
  if (!data) return html`<div class="loading">Loading…</div>`;

  const addOne = (name) => {
    queueForNextScan([name]);
    setAdded((prev) => new Set(prev).add(name));
  };
  const addAll = () => {
    const names = data.rows.map((r) => r.name);
    queueForNextScan(names);
    setAdded(new Set(names));
  };

  return html`<div class="view-scroll">
    <div class="card">
      <div style="display:flex;justify-content:space-between;align-items:flex-start">
        <${CardTitle} topic="discovered.how">Newly discovered<//>
        ${data.rows.length ? html`<button class="btn btn-sm" onClick=${addAll}>
          Add all ${data.rows.length} to next scan</button>` : null}
      </div>
      <p class="subtle" style="margin:0 0 10px">
        Found via certificate SAN lists and reverse DNS, never probed directly —
        add the ones worth enumerating to your next scan's target list.
      </p>

      ${!data.rows.length ? html`<p class="subtle">
        Nothing discovered outside what this scan already enumerated. Turn on
        “Correlate assets” on the scan form if this run didn't use it.</p>` : null}

      ${data.rows.length ? html`<div class="scroll-x"><table class="plain">
        <thead><tr><th>Name</th><th>Found via</th><th></th></tr></thead>
        <tbody>${data.rows.map((r) => html`<tr>
          <td><code>${r.name}</code></td>
          <td><span class="chip" data-state="info">
            ${r.via === 'certificate' ? 'Certificate SAN' : 'Reverse DNS'}</span>
            ${r.ip ? html` <span class="subtle">(${r.ip})</span>` : null}
          </td>
          <td class="right">
            ${added.has(r.name)
              ? html`<span class="subtle">✓ queued</span>`
              : html`<button class="btn btn-sm" onClick=${() => addOne(r.name)}>
                  Add to next scan</button>`}
          </td>
        </tr>`)}</tbody>
      </table></div>` : null}
    </div>
  </div>`;
}

export function takePendingScanTargets() {
  let names = [];
  try {
    names = JSON.parse(window.localStorage.getItem(PENDING_KEY) || '[]');
  } catch {
    names = [];
  }
  try {
    window.localStorage.removeItem(PENDING_KEY);
  } catch {
    // Nothing to clear if storage was never reachable.
  }
  return names;
}
