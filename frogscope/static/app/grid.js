// The data grid: sticky header, a filter widget per column type, sortable
// headers, and a row-click drawer.
//
// Filter semantics deliberately match the existing frogy report
// (header.html:5871): AND across columns, OR within one column's values. The
// difference is that this version is typed and runs in SQL over the whole run,
// not over the rendered page.

import { h } from 'preact';
import { useState } from 'preact/hooks';
import htm from 'htm';
import { boolMeta, formatCell, originHealthMeta, responseClassMeta, truncate } from './lib.js';
import { SeverityChip } from './risk.js';

const html = htm.bind(h);

function Cell({ column, value, row }) {
  if (value === null || value === undefined || value === '') {
    return html`<span class="subtle">—</span>`;
  }

  if (column.key === 'response_class') {
    const meta = responseClassMeta(value);
    return html`<span class="chip" data-state=${meta.state}>${meta.glyph} ${meta.label}</span>`;
  }

  // Severity always carries a glyph and a label, never colour alone.
  if (column.key === 'risk_band' || column.key === 'worst_severity'
      || column.key === 'eol_worst_severity' || column.key === 'takeover_grade') {
    return html`<${SeverityChip} severity=${
      column.key === 'takeover_grade'
        ? ({ high: 'critical', medium: 'high', low: 'medium' }[value] || 'info')
        : value} />`;
  }

  if (column.key === 'risk_score') {
    const n = Number(value);
    const token = n >= 45 ? 'var(--status-critical)'
      : n >= 25 ? 'var(--status-high)'
      : n >= 10 ? 'var(--status-medium)' : 'var(--color-text-subtle)';
    return html`<span class="num" style=${`color:${token};font-weight:600`}>${n}</span>`;
  }

  if (column.key === 'origin_health') {
    const meta = originHealthMeta(value);
    return html`<span class="chip" data-state=${meta.state}>${meta.glyph} ${meta.label}</span>`;
  }

  if (column.type === 'bool') {
    const meta = boolMeta(column.key, value);
    if (meta.label === 'no') return html`<span class="subtle">no</span>`;
    return html`<span class="chip" data-state=${meta.state}>${meta.glyph} yes</span>`;
  }

  if (column.key === 'status_code') {
    const n = Number(value);
    const state = n >= 500 ? 'warn' : n >= 400 ? 'neutral' : 'info';
    return html`<span class="chip" data-state=${state}>${value}</span>`;
  }

  if (column.type === 'list') {
    const items = Array.isArray(value) ? value : [value];
    if (!items.length) return html`<span class="subtle">—</span>`;
    const shown = items.slice(0, 4);
    return html`<span class="chip-list">
      ${shown.map((item) => html`<span class="chip">${truncate(item, 28)}</span>`)}
      ${items.length > shown.length
        && html`<span class="chip subtle">+${items.length - shown.length}</span>`}
    </span>`;
  }

  if (column.type === 'url' && String(value).startsWith('http')) {
    return html`<a href=${value} target="_blank" rel="noreferrer noopener"
                   title=${value}>${truncate(value, 60)}</a>`;
  }

  const text = formatCell(column, value);
  return html`<span title=${String(value)}>${truncate(text, 120)}</span>`;
}

// ── Per-column filter widgets ───────────────────────────────────────────────

function FilterWidget({ column, value, facet, onChange }) {
  const active = value !== undefined && value !== null && value !== ''
    && !(Array.isArray(value) && !value.length)
    && !(typeof value === 'object' && !Array.isArray(value)
         && !Object.values(value).some((v) => v !== '' && v !== undefined));
  const cls = active ? 'active' : '';

  // Low-cardinality enums get a select populated from the live facet counts, so
  // you can see how many rows each value has before choosing it.
  if (column.filter === 'multiselect' && facet && facet.length) {
    const current = Array.isArray(value) ? value[0] : (value ?? '');
    return html`<select class=${cls} value=${String(current)}
      onChange=${(e) => onChange(e.target.value === '' ? null : [e.target.value])}>
      <option value="">all</option>
      ${facet.map((opt) => html`
        <option value=${String(opt.value)}>${opt.label} (${opt.count})</option>`)}
    </select>`;
  }

  if (column.filter === 'bool') {
    const current = Array.isArray(value) ? value[0] : (value ?? '');
    return html`<select class=${cls} value=${String(current)}
      onChange=${(e) => onChange(e.target.value === '' ? null : [e.target.value])}>
      <option value="">all</option>
      <option value="true">yes</option>
      <option value="false">no</option>
    </select>`;
  }

  if (column.filter === 'range') {
    const spec = (value && typeof value === 'object' && !Array.isArray(value)) ? value : {};
    return html`<span style="display:flex;gap:3px">
      <input class=${cls} type="number" placeholder="min" value=${spec.min ?? ''}
        onInput=${(e) => onChange({ ...spec, min: e.target.value })} />
      <input class=${cls} type="number" placeholder="max" value=${spec.max ?? ''}
        onInput=${(e) => onChange({ ...spec, max: e.target.value })} />
    </span>`;
  }

  // Array columns get any/all/none semantics. A plain text match against the
  // JSON blob would ignore element boundaries and mislead.
  if (column.filter === 'tokens') {
    const spec = (value && typeof value === 'object') ? value : { values: [], mode: 'any' };
    const text = (spec.values || []).join(',');
    return html`<span style="display:flex;gap:3px">
      <select class=${cls} style="max-width:64px" value=${spec.mode || 'any'}
        onChange=${(e) => onChange({ ...spec, mode: e.target.value })}>
        <option value="any">any</option>
        <option value="all">all</option>
        <option value="none">none</option>
      </select>
      <input class=${cls} placeholder="a,b" value=${text}
        onInput=${(e) => onChange({
          mode: spec.mode || 'any',
          values: e.target.value.split(',').map((s) => s.trim()).filter(Boolean),
        })} />
    </span>`;
  }

  const current = Array.isArray(value)
    ? String(value[0] ?? '').replace(/^~/, '')
    : String(value ?? '').replace(/^~/, '');
  return html`<input class=${cls} placeholder="contains" value=${current}
    onInput=${(e) => onChange(e.target.value ? [`~${e.target.value}`] : null)} />`;
}

// ── Grid ────────────────────────────────────────────────────────────────────

export function DataGrid({ columns, rows, sort, filters, facets, onSort, onFilter, onRow,
                          scrollRef }) {
  const [showFilters, setShowFilters] = useState(true);

  if (!columns.length) {
    return html`<div class="empty"><h2>No columns selected</h2>
      <p class="muted">Pick some in the column chooser.</p></div>`;
  }

  const sortKey = String(sort || '').replace(/^[-+]/, '');
  const sortDesc = String(sort || '').startsWith('-');

  return html`<div class="grid-wrap" ref=${scrollRef}>
    <table class="grid">
      <thead>
        <tr>
          ${columns.map((col) => html`
            <th style=${`min-width:${col.width}px`}
                title=${col.description || col.label}
                onClick=${() => onSort(sortKey === col.key && !sortDesc ? `-${col.key}` : col.key)}>
              ${col.label}
              ${sortKey === col.key
                && html`<span class="sort-arrow">${sortDesc ? '▾' : '▴'}</span>`}
            </th>`)}
        </tr>
        ${showFilters && html`<tr class="filters">
          ${columns.map((col) => html`<th>
            <${FilterWidget} column=${col} value=${filters[col.key]}
              facet=${facets[col.key]}
              onChange=${(v) => onFilter(col.key, v)} />
          </th>`)}
        </tr>`}
      </thead>
      <tbody>
        ${rows.map((row) => html`
          <tr key=${row.endpoint_key} onClick=${() => onRow && onRow(row)}
              style="cursor:pointer">
            ${columns.map((col) => html`
              <td class=${col.align === 'right' ? 'cell-num' : ''}>
                <${Cell} column=${col} value=${row[col.key]} row=${row} />
              </td>`)}
          </tr>`)}
        ${!rows.length && html`<tr><td colspan=${columns.length}>
          <div class="empty"><h2>Nothing matches</h2>
          <p class="muted">Loosen or clear a filter.</p></div>
        </td></tr>`}
      </tbody>
    </table>
  </div>`;
}

export function ColumnPicker({ catalog, groups, visible, presets, onChange, onClose }) {
  const [search, setSearch] = useState('');
  const needle = search.toLowerCase();

  const byGroup = {};
  for (const col of catalog) {
    if (needle && !col.label.toLowerCase().includes(needle)
        && !col.key.toLowerCase().includes(needle)) continue;
    (byGroup[col.group] = byGroup[col.group] || []).push(col);
  }

  const toggle = (key) => {
    onChange(visible.includes(key)
      ? visible.filter((k) => k !== key)
      : [...visible, key]);
  };

  // Both master and per-group tickboxes act on what's currently on screen —
  // the filtered-by-search set, not the whole catalog — so they stay
  // consistent with each other and with what the user is actually looking
  // at. `catalog.map(...)`'s own "Everything" button above still means the
  // literal, unfiltered, whole-catalog case.
  const toggleKeys = (keys) => {
    const allOn = keys.every((k) => visible.includes(k));
    onChange(allOn
      ? visible.filter((k) => !keys.includes(k))
      : [...new Set([...visible, ...keys])]);
  };

  const orderedGroups = Object.keys(byGroup).sort(
    (a, b) => ((groups[a] && groups[a].order) || 99) - ((groups[b] && groups[b].order) || 99));
  const shownKeys = orderedGroups.flatMap((g) => byGroup[g].map((c) => c.key));
  const allShown = shownKeys.length > 0 && shownKeys.every((k) => visible.includes(k));

  return html`<div class="drawer-backdrop" onClick=${onClose}>
    <div class="drawer" style="width:min(560px,100vw)" onClick=${(e) => e.stopPropagation()}>
      <div class="drawer-head">
        <strong>Columns</strong>
        <span class="muted">${visible.length} shown</span>
        <span class="spacer"></span>
        <button class="btn btn-sm" onClick=${onClose}>Done</button>
      </div>
      <div class="drawer-body">
        <input class="input" style="width:100%;margin-bottom:10px" placeholder="Filter columns…"
          value=${search} onInput=${(e) => setSearch(e.target.value)} />

        <div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:10px">
          ${Object.entries(presets || {}).map(([id, preset]) => html`
            <button class="btn btn-sm" onClick=${() => onChange(preset.columns)}>
              ${preset.label}
            </button>`)}
          <button class="btn btn-sm"
            onClick=${() => onChange(catalog.map((c) => c.key))}>Everything</button>
        </div>

        <label class="facet-row" style="margin-bottom:14px;font-weight:600">
          <input type="checkbox" checked=${allShown}
            onChange=${() => toggleKeys(shownKeys)} />
          <span class="label">Select all${needle ? ' (matching)' : ''}</span>
        </label>

        ${orderedGroups.map((group) => {
          const groupKeys = byGroup[group].map((c) => c.key);
          const groupAll = groupKeys.every((k) => visible.includes(k));
          return html`<div style="margin-bottom:14px">
            <label class="facet-row" style="font-weight:600">
              <input type="checkbox" checked=${groupAll}
                onChange=${() => toggleKeys(groupKeys)} />
              <span class="label facet-title" style="margin:0">
                ${(groups[group] && groups[group].label) || group}</span>
            </label>
            ${byGroup[group].map((col) => html`
              <label class="facet-row" style="padding-left:22px">
                <input type="checkbox" checked=${visible.includes(col.key)}
                  onChange=${() => toggle(col.key)} />
                <span class="label" title=${col.description}>${col.label}</span>
                ${col.description && html`<span class="count">?</span>`}
              </label>`)}
          </div>`;
        })}
      </div>
    </div>
  </div>`;
}
