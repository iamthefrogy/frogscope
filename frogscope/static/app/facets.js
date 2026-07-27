// Facet sidebar.
//
// Counts arrive already cross-filtered by the server: each facet is computed
// against every OTHER active filter but not its own. That is what stops a facet
// zeroing itself out the moment you pick a value in it — without it you could
// select "cloudflare" and then no longer see, or switch to, any other CDN.

import { h } from 'preact';
import { useState } from 'preact/hooks';
import htm from 'htm';
import { boolMeta, responseClassMeta } from './lib.js';

const html = htm.bind(h);

const PRIORITY = [
  'response_class', 'env', 'port_category', 'cdn_name', 'hosting_provider',
  'auth_surface_type', 'origin_health', 'status_code', 'scheme', 'zone',
  'title_class', 'webserver', 'port', 'origin_exposed', 'no_waf',
  'serves_content', 'mgmt_surface', 'remote_access_exposed', 'scan_artifact',
  'cf_alias_port',
];

function labelFor(key, option) {
  if (key === 'response_class') {
    const meta = responseClassMeta(option.value);
    return `${meta.glyph} ${meta.label}`;
  }
  if (typeof option.value === 'boolean') {
    return option.value ? boolMeta(key, true).label : 'no';
  }
  return option.label;
}

/** The selected values for one facet, whatever shape the filter takes.
 *
 * A plain array (an enum filter) and `{values: [...], mode}` (a list-column
 * filter) both occur. The old expression was `filter.values || filter`, which on
 * an ARRAY returns `Array.prototype.values` — a truthy function. Stringifying that
 * gave a chosen set of `["function Values() { [native code] }"]`, so no checkbox
 * ever matched and no tick ever appeared.
 */
function selectedValues(filter) {
  if (filter === null || filter === undefined || filter === '') return [];
  if (Array.isArray(filter)) return filter;
  if (typeof filter === 'object') return Array.isArray(filter.values) ? filter.values : [];
  return [filter];
}


function FacetGroup({ column, options, selected, onToggle }) {
  const [open, setOpen] = useState(true);
  const [search, setSearch] = useState('');

  const chosen = new Set((selected || []).map(String));

  // Counts change every time a filter is applied, and the server returns options
  // ordered by count. Re-sorting on each response made the row you had just
  // clicked jump somewhere else — so the tick appeared to land on a different
  // option and the whole panel visibly shifted.
  //
  // So: selected options are pinned to the top, and everything else is ordered by
  // LABEL rather than by count. Label order does not move when counts move.
  const ordered = [...options].sort((a, b) => {
    const aOn = chosen.has(String(a.value));
    const bOn = chosen.has(String(b.value));
    if (aOn !== bOn) return aOn ? -1 : 1;
    return String(a.label).localeCompare(String(b.label), undefined,
                                         { numeric: true });
  });

  // A value you selected can drop out of the response entirely once it is the only
  // thing left — which would remove the row and with it the only way to unselect
  // it. Add it back with a zero count.
  const present = new Set(ordered.map((o) => String(o.value)));
  for (const value of chosen) {
    if (!present.has(value)) {
      ordered.unshift({ value, label: value, count: 0 });
    }
  }

  const needle = search.toLowerCase();
  const shown = ordered.filter(
    (o) => !needle || String(o.label).toLowerCase().includes(needle));
  // Selected options are pinned first, so the cap can never hide one.
  const limited = shown.slice(0, 14);

  return html`<div class="facet">
    <div class="facet-title" onClick=${() => setOpen(!open)}>
      <span>${column.label}</span>
      <span>${chosen.size ? html`<span class="count">${chosen.size} on</span>` : ''}
        ${open ? '▾' : '▸'}</span>
    </div>
    ${open && html`<div>
      ${options.length > 14 && html`
        <input class="input" style="width:100%;margin-bottom:4px;font-size:11px"
          placeholder="find…" value=${search}
          onInput=${(e) => setSearch(e.target.value)} />`}
      ${limited.map((option) => html`
        <label class="facet-row" key=${String(option.value)}
          data-on=${chosen.has(String(option.value)) ? '1' : null}>
          <input type="checkbox" checked=${chosen.has(String(option.value))}
            onChange=${() => onToggle(column.key, option.value)} />
          <span class="label" title=${option.label}>${labelFor(column.key, option)}</span>
          <span class="count">${option.count.toLocaleString()}</span>
        </label>`)}
      ${shown.length > limited.length && html`
        <div class="subtle" style="font-size:11px;padding:2px 3px">
          +${shown.length - limited.length} more — use the search box
        </div>`}
    </div>`}
  </div>`;
}

export function Facets({ catalog, facets, filters, onToggle, onClear, onCollapse }) {
  const byKey = Object.fromEntries(catalog.map((c) => [c.key, c]));
  // Group order is fixed: PRIORITY first, then the rest alphabetically. Relying on
  // `Object.keys` order let the sidebar reshuffle between responses.
  const keys = [
    ...PRIORITY.filter((k) => facets[k]),
    ...Object.keys(facets).filter((k) => !PRIORITY.includes(k)).sort(),
  ];

  const activeCount = Object.values(filters || {}).filter((v) =>
    v !== null && v !== undefined && v !== ''
    && !(Array.isArray(v) && !v.length)).length;

  return html`<aside class="facets">
    <div style="display:flex;align-items:center;gap:6px;margin-bottom:12px">
      ${onCollapse && html`<button class="btn btn-sm" title="Hide the filter sidebar"
        onClick=${onCollapse} style="padding:5px 7px">◂</button>`}
      <strong style="font-size:12px">Filters</strong>
      <span class="spacer"></span>
      ${activeCount > 0 && html`
        <button class="btn btn-sm" onClick=${onClear}>Clear ${activeCount}</button>`}
    </div>
    ${!keys.length && html`<div class="subtle" style="font-size:12px">
      No facets for this run.</div>`}
    ${keys.map((key) => byKey[key] && html`
      <${FacetGroup} key=${key} column=${byKey[key]} options=${facets[key]}
        selected=${selectedValues(filters[key])}
        onToggle=${onToggle} />`)}
  </aside>`;
}
