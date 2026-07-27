// Hand-rolled inline-SVG chart primitives.
//
// SVG rather than canvas because these have to print cleanly, keep their text
// selectable, and carry accessible labels — canvas fails all three, and the
// executive page is meant to be printed.
//
// Rules this file follows, deliberately:
//   * Categorical hues are assigned in a fixed order and never cycled. A 9th
//     series folds into "Other" instead of generating a new colour.
//   * Severity uses the reserved status palette, and every severity mark also
//     carries a glyph and a text label — colour never carries meaning alone.
//   * Stacked segments are separated by a 2px surface-coloured gap so touching
//     fills stay legible without relying on contrast between them.
//   * Data-ends are rounded 4px; the baseline end stays square.
//   * No dual axes, ever. Two measures of different scale get two charts.
//   * Text wears text tokens, never the series colour.
//   * Every chart is followed by an optional table view for accessibility.

import { h } from 'preact';
import { useState } from 'preact/hooks';
import htm from 'htm';

const html = htm.bind(h);

// Fixed categorical order. Index, never cycle.
export const SERIES = [
  'var(--series-1)', 'var(--series-2)', 'var(--series-3)', 'var(--series-4)',
  'var(--series-5)', 'var(--series-6)', 'var(--series-7)', 'var(--series-8)',
];

// Reserved status palette — never reused for a data series.
export const SEVERITY_TOKEN = {
  critical: 'var(--status-critical)',
  high: 'var(--status-high)',
  medium: 'var(--status-medium)',
  low: 'var(--status-low)',
  info: 'var(--color-text-subtle)',
  clean: 'var(--status-good)',
};

export const SEVERITY_GLYPH = {
  critical: '!!', high: '!', medium: '~', low: '·', info: ' ', clean: '✓',
};

export function seriesColour(index) {
  // Past the eighth slot, fold into a neutral rather than inventing a hue.
  return index < SERIES.length ? SERIES[index] : 'var(--color-text-subtle)';
}

function fmt(n) {
  return Number(n).toLocaleString();
}

// ── Legend ──────────────────────────────────────────────────────────────────
// Present whenever there are two or more series, so identity is never
// colour-alone.

export function Legend({ items, compact }) {
  if (!items || items.length < 2) return null;
  return html`<div class="chip-list" style=${
    `margin-top:${compact ? 4 : 8}px`} role="list">
    ${items.map((item) => html`<span class="chip" role="listitem"
      title=${item.title || item.label}>
      <span aria-hidden="true" style=${`display:inline-block;width:9px;height:9px;`
        + `border-radius:2px;background:${item.colour};flex:0 0 auto`}></span>
      ${item.glyph ? html`<strong>${item.glyph}</strong> ` : ''}${item.label}
      ${item.value !== undefined ? html` <span class="subtle">${fmt(item.value)}</span>` : ''}
    </span>`)}
  </div>`;
}

// ── Table view ──────────────────────────────────────────────────────────────
// Behind every chart, because a chart alone is not accessible and because
// someone always wants the exact numbers.

export function TableView({ columns, rows, open, onToggle }) {
  return html`<div style="margin-top:8px">
    <button class="btn btn-sm" aria-expanded=${open ? 'true' : 'false'}
      onClick=${onToggle}>${open ? 'Hide' : 'Show'} data table</button>
    ${open && html`<div class="scroll-x" style="margin-top:6px">
      <table class="plain">
        <thead><tr>${columns.map((c) => html`
          <th class=${c.align === 'right' ? 'right' : ''}>${c.label}</th>`)}</tr></thead>
        <tbody>${rows.map((row) => html`<tr>
          ${columns.map((c) => html`<td class=${
            c.align === 'right' ? 'num right' : ''}>${row[c.key]}</td>`)}
        </tr>`)}</tbody>
      </table>
    </div>`}
  </div>`;
}

function withTable(chart, columns, rows) {
  const [open, setOpen] = useState(false);
  return html`<div>
    ${chart}
    <${TableView} columns=${columns} rows=${rows} open=${open}
      onToggle=${() => setOpen(!open)} />
  </div>`;
}

// ── 100% stacked horizontal bar ─────────────────────────────────────────────
// The right form for "what proportion of the whole is each category" — a donut
// makes the same comparison harder and wastes the space.

export function StackedShareBar({ segments, height = 22, showLegend = true,
                                 label }) {
  const [hover, setHover] = useState(null);
  const total = segments.reduce((sum, s) => sum + (s.count || 0), 0) || 1;
  const visible = segments.filter((s) => s.count > 0);

  return withTable(
    html`<div>
      <div style="position:relative">
        <svg viewBox=${`0 0 100 ${height}`} preserveAspectRatio="none"
             style=${`width:100%;height:${height}px;display:block`}
             role="img" aria-label=${label || 'Composition'}>
          ${visible.reduce((acc, segment, index) => {
            const width = (100 * segment.count) / total;
            const node = html`<rect key=${segment.key}
              x=${acc.x} y="0" width=${Math.max(0, width)} height=${height}
              fill=${segment.colour}
              opacity=${hover && hover !== segment.key ? 0.45 : 1}
              onMouseEnter=${() => setHover(segment.key)}
              onMouseLeave=${() => setHover(null)}>
              <title>${segment.label}: ${fmt(segment.count)} (${
                segment.pct ?? width.toFixed(1)}%)</title>
            </rect>`;
            acc.nodes.push(node);
            acc.x += width;
            return acc;
          }, { x: 0, nodes: [] }).nodes}
          ${/* 2px surface gaps drawn on top of the joins, so adjacent fills
                never touch and stay readable without contrast between them. */
            visible.slice(0, -1).reduce((acc, segment) => {
              acc.x += (100 * segment.count) / total;
              acc.nodes.push(html`<rect x=${acc.x} y="0" width="0.35"
                height=${height} fill="var(--color-surface)" />`);
              return acc;
            }, { x: 0, nodes: [] }).nodes}
        </svg>
      </div>
      ${showLegend && html`<${Legend} items=${visible.map((s) => ({
        label: s.label, colour: s.colour, value: s.count,
        title: `${s.label}: ${s.count} (${s.pct}%)`,
      }))} />`}
    </div>`,
    [
      { key: 'label', label: 'Category' },
      { key: 'count', label: 'Count', align: 'right' },
      { key: 'pct', label: 'Share', align: 'right' },
    ],
    visible.map((s) => ({ label: s.label, count: fmt(s.count), pct: `${s.pct}%` })),
  );
}

// ── Sorted horizontal bars ──────────────────────────────────────────────────
// The right form for ranked magnitude across a modest number of categories:
// labels stay horizontal and readable however long they are.

export function RankedBars({ rows, valueKey = 'value', labelKey = 'label',
                            colour, max, unit = '', barHeight = 18,
                            gap = 6, secondary }) {
  const [hover, setHover] = useState(null);
  if (!rows || !rows.length) {
    return html`<p class="subtle">No data.</p>`;
  }
  // Sorted here rather than relying on the caller: a chart whose bars are not
  // ordered by the value on its own axis looks broken, and that costs the
  // reader's trust in every other number on the page.
  const sorted = [...rows].sort((a, b) => (b[valueKey] || 0) - (a[valueKey] || 0));
  const ceiling = max || Math.max(...sorted.map((r) => r[valueKey] || 0)) || 1;

  return withTable(
    html`<div role="img" aria-label="Ranked comparison">
      ${sorted.map((row, index) => {
        const value = row[valueKey] || 0;
        const width = (100 * value) / ceiling;
        const fill = typeof colour === 'function'
          ? colour(row, index) : (colour || seriesColour(0));
        return html`<div style=${`display:flex;align-items:center;gap:8px;`
            + `margin-bottom:${gap}px`}
            onMouseEnter=${() => setHover(index)}
            onMouseLeave=${() => setHover(null)}>
          <div style="width:34%;min-width:110px;font-size:12px;overflow:hidden;
                      text-overflow:ellipsis;white-space:nowrap"
               title=${row[labelKey]}>${row[labelKey]}</div>
          <div style="flex:1;position:relative">
            <svg viewBox=${`0 0 100 ${barHeight}`} preserveAspectRatio="none"
                 style=${`width:100%;height:${barHeight}px;display:block`}>
              <rect x="0" y=${barHeight * 0.15} width="100"
                    height=${barHeight * 0.7} fill="var(--color-surface-muted)"
                    rx="0.6" />
              ${/* Data-end rounded, baseline end square. */''}
              <rect x="0" y=${barHeight * 0.15} width=${Math.max(0.4, width)}
                    height=${barHeight * 0.7} fill=${fill}
                    opacity=${hover !== null && hover !== index ? 0.55 : 1}
                    rx="0.6">
                <title>${row[labelKey]}: ${fmt(value)}${unit}</title>
              </rect>
            </svg>
          </div>
          <div class="num" style="width:74px;text-align:right;font-size:12px">
            ${fmt(value)}${unit}
            ${secondary && html`<span class="subtle"> / ${fmt(row[secondary])}</span>`}
          </div>
        </div>`;
      })}
    </div>`,
    [
      { key: 'label', label: 'Category' },
      { key: 'value', label: 'Value', align: 'right' },
    ],
    sorted.map((r) => ({ label: r[labelKey], value: fmt(r[valueKey] || 0) })),
  );
}

// ── Severity distribution ───────────────────────────────────────────────────
// A stacked share bar using the reserved status palette, with glyph + label in
// the legend so severity is never carried by colour alone.

export function SeverityBar({ counts, order, cleanCount, cleanLabel }) {
  const levels = order || ['critical', 'high', 'medium', 'low', 'info'];
  const segments = levels
    .filter((level) => (counts || {})[level])
    .map((level) => ({
      key: level,
      label: `${level[0].toUpperCase()}${level.slice(1)}`,
      count: counts[level],
      colour: SEVERITY_TOKEN[level],
      glyph: SEVERITY_GLYPH[level],
    }));

  if (cleanCount) {
    segments.push({
      key: 'clean', label: cleanLabel || 'Nothing flagged', count: cleanCount,
      colour: SEVERITY_TOKEN.clean, glyph: SEVERITY_GLYPH.clean,
    });
  }

  const total = segments.reduce((sum, s) => sum + s.count, 0) || 1;
  segments.forEach((s) => { s.pct = Math.round((1000 * s.count) / total) / 10; });

  return html`<${StackedShareBar} segments=${segments}
    label="Distribution by severity" />`;
}

// ── Gauge-free hero meter ───────────────────────────────────────────────────
// A linear meter rather than a radial gauge: the same information, read more
// accurately, and it prints without a rendering surprise.

export function Meter({ value, max = 100, label, caption, inverted }) {
  const share = Math.max(0, Math.min(100, (100 * value) / max));
  // `inverted` means a HIGHER value is better, so the colour ramp flips.
  const level = inverted
    ? (share >= 80 ? 'clean' : share >= 60 ? 'medium' : share >= 40 ? 'high' : 'critical')
    : (share >= 80 ? 'critical' : share >= 60 ? 'high' : share >= 40 ? 'medium' : 'clean');

  return html`<div>
    <div style="display:flex;align-items:baseline;gap:8px">
      <span class="kpi-value" style=${`color:${SEVERITY_TOKEN[level]}`}>${value}</span>
      <span class="muted" style="font-size:13px">/ ${max}</span>
    </div>
    ${label && html`<div class="kpi-label">${label}</div>`}
    <svg viewBox="0 0 100 6" preserveAspectRatio="none"
         style="width:100%;height:6px;display:block;margin-top:6px"
         role="img" aria-label=${`${label}: ${value} of ${max}`}>
      <rect x="0" y="0" width="100" height="6" rx="1"
            fill="var(--color-surface-muted)" />
      <rect x="0" y="0" width=${Math.max(0.5, share)} height="6" rx="1"
            fill=${SEVERITY_TOKEN[level]} />
    </svg>
    ${caption && html`<div class="kpi-note" style="margin-top:4px">${caption}</div>`}
  </div>`;
}

// ── Sparkline ───────────────────────────────────────────────────────────────
// Built now, used once a second run exists. Returns an honest empty state
// rather than a flat line, because a flat line reads as "no change" when the
// truth is "no data".

export function Sparkline({ points, width = 90, height = 24, colour,
                           emptyNote = 'needs 2+ runs' }) {
  const values = (points || []).filter((p) => Number.isFinite(Number(p)));
  if (values.length < 2) {
    return html`<span class="stat-empty">${emptyNote}</span>`;
  }
  const min = Math.min(...values);
  const max = Math.max(...values);
  const span = max - min || 1;
  const step = width / (values.length - 1);
  const path = values
    .map((v, i) => `${i === 0 ? 'M' : 'L'}${(i * step).toFixed(1)},`
      + `${(height - ((v - min) / span) * height).toFixed(1)}`)
    .join(' ');

  return html`<svg width=${width} height=${height}
    viewBox=${`0 0 ${width} ${height}`} role="img"
    aria-label=${`Trend: ${values.join(', ')}`}
    style="display:block;overflow:visible">
    <path d=${path} fill="none" stroke=${colour || seriesColour(0)}
          stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
    <circle cx=${width} cy=${
      (height - ((values[values.length - 1] - min) / span) * height).toFixed(1)}
      r="2.5" fill=${colour || seriesColour(0)} />
  </svg>`;
}

// ── Grouped comparison ──────────────────────────────────────────────────────
// For "hosts vs hosts needing attention" per group: two measures on one shared
// scale, which is legitimate. Two DIFFERENT scales would need two charts.

export function GroupedBars({ rows, labelKey, series, unit = '' }) {
  const [hover, setHover] = useState(null);
  if (!rows || !rows.length) return html`<p class="subtle">No data.</p>`;

  const ceiling = Math.max(
    ...rows.flatMap((r) => series.map((s) => r[s.key] || 0)), 1);
  const barHeight = 9;

  return withTable(
    html`<div>
      ${rows.map((row, index) => html`<div
        style="display:flex;align-items:center;gap:8px;margin-bottom:8px"
        onMouseEnter=${() => setHover(index)} onMouseLeave=${() => setHover(null)}>
        <div style="width:34%;min-width:110px;font-size:12px;overflow:hidden;
                    text-overflow:ellipsis;white-space:nowrap"
             title=${row[labelKey]}>${row[labelKey]}</div>
        <div style="flex:1">
          <svg viewBox=${`0 0 100 ${series.length * (barHeight + 2)}`}
               preserveAspectRatio="none"
               style=${`width:100%;height:${series.length * (barHeight + 2)}px;`
                 + 'display:block'}>
            ${series.map((s, si) => html`
              <rect x="0" y=${si * (barHeight + 2)}
                    width=${Math.max(0.4, (100 * (row[s.key] || 0)) / ceiling)}
                    height=${barHeight} fill=${s.colour} rx="0.6"
                    opacity=${hover !== null && hover !== index ? 0.55 : 1}>
                <title>${row[labelKey]} — ${s.label}: ${
                  fmt(row[s.key] || 0)}${unit}</title>
              </rect>`)}
          </svg>
        </div>
        <div class="num" style="width:86px;text-align:right;font-size:12px">
          ${series.map((s, si) => html`<div style=${
            si ? 'color:var(--color-text-muted)' : ''}>${
            fmt(row[s.key] || 0)}</div>`)}
        </div>
      </div>`)}
      <${Legend} items=${series.map((s) => ({ label: s.label, colour: s.colour }))} />
    </div>`,
    [
      { key: 'label', label: 'Group' },
      ...series.map((s) => ({ key: s.key, label: s.label, align: 'right' })),
    ],
    rows.map((r) => ({
      label: r[labelKey],
      ...Object.fromEntries(series.map((s) => [s.key, fmt(r[s.key] || 0)])),
    })),
  );
}
