// Formatting, filter-state serialisation, and the omnibox parser.

export const NBSP = ' ';

export function num(value) {
  if (value === null || value === undefined || value === '') return '';
  const n = Number(value);
  return Number.isFinite(n) ? n.toLocaleString() : String(value);
}

export function bytes(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return '';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

export function ms(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return '';
  if (n < 1000) return `${n.toFixed(0)} ms`;
  return `${(n / 1000).toFixed(2)} s`;
}

export function when(value) {
  if (!value) return '';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return String(value);
  return d.toISOString().replace('T', ' ').slice(0, 19);
}

export function truncate(text, limit = 90) {
  const s = String(text ?? '');
  return s.length > limit ? `${s.slice(0, limit - 1)}…` : s;
}

export function titleCase(text) {
  return String(text ?? '')
    .replace(/[_-]+/g, ' ')
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

// ── Semantics of derived enums, for chip colouring and plain-English labels ──
// Colour is never the only signal: every chip also carries a glyph and text.

const RESPONSE_CLASS_META = {
  live_content:       { label: 'Live content',        state: 'info',    glyph: '●' },
  auth_required:      { label: 'Login required',      state: 'good',    glyph: '🔒' },
  waf_blocked:        { label: 'Blocked by WAF',      state: 'good',    glyph: '🛡' },
  waf_challenge:      { label: 'WAF challenge',       state: 'good',    glyph: '🛡' },
  scan_artifact:      { label: 'Scan artefact',       state: 'neutral', glyph: '∅' },
  origin_unreachable: { label: 'Origin unreachable',  state: 'bad',     glyph: '▲' },
  origin_tls_failure: { label: 'Origin TLS broken',   state: 'warn',    glyph: '▲' },
  server_error:       { label: 'Server error',        state: 'warn',    glyph: '!' },
  not_found:          { label: 'Not found',           state: 'neutral', glyph: '·' },
  forbidden:          { label: 'Forbidden',           state: 'neutral', glyph: '·' },
  client_error:       { label: 'Client error',        state: 'neutral', glyph: '·' },
  redirect_only:      { label: 'Redirect only',       state: 'neutral', glyph: '→' },
  parked:             { label: 'Parked',              state: 'neutral', glyph: '·' },
  dead:               { label: 'No response',         state: 'neutral', glyph: '×' },
};

export function responseClassMeta(value) {
  return RESPONSE_CLASS_META[value]
    || { label: titleCase(value), state: 'neutral', glyph: '·' };
}

const ORIGIN_HEALTH_META = {
  ok:          { label: 'OK',                    state: 'good',    glyph: '✓' },
  dns_missing: { label: 'Origin DNS missing',    state: 'bad',     glyph: '▲' },
  tls_broken:  { label: 'Origin TLS broken',     state: 'warn',    glyph: '▲' },
  unreachable: { label: 'Origin unreachable',    state: 'warn',    glyph: '▲' },
  unknown:     { label: 'Unknown',               state: 'neutral', glyph: '?' },
};

export function originHealthMeta(value) {
  return ORIGIN_HEALTH_META[value]
    || { label: titleCase(value), state: 'neutral', glyph: '?' };
}

// Booleans where "true" is the concerning state, so the chip reads red.
export const BAD_WHEN_TRUE = new Set([
  'origin_exposed', 'no_waf', 'unprotected', 'no_tls_redirect', 'mgmt_surface',
  'remote_access_exposed', 'version_disclosure', 'intra_run_inconsistent',
  'scheme_conflict', 'redirect_offsite',
]);

export const GOOD_WHEN_TRUE = new Set([
  'waf_protected', 'federated_auth', 'redirects_to_https', 'behind_proxy',
  'ipv6_enabled', 'serves_content',
]);

export function boolMeta(column, value) {
  const truthy = value === true || value === 1;
  if (!truthy) return { label: 'no', state: 'neutral', glyph: '' };
  if (BAD_WHEN_TRUE.has(column)) return { label: 'yes', state: 'bad', glyph: '▲' };
  if (GOOD_WHEN_TRUE.has(column)) return { label: 'yes', state: 'good', glyph: '✓' };
  return { label: 'yes', state: 'info', glyph: '●' };
}

// ── Cell rendering ──────────────────────────────────────────────────────────

export function formatCell(column, value) {
  if (value === null || value === undefined || value === '') return '';
  switch (column.type) {
    case 'int':
    case 'float':
      return column.format === 'ms' ? ms(value) : num(value);
    case 'bool':
      return value === true || value === 1 ? 'yes' : 'no';
    case 'datetime':
      return when(value);
    case 'list':
      return Array.isArray(value) ? value.join(', ') : String(value);
    default:
      return String(value);
  }
}

// ── URL state ───────────────────────────────────────────────────────────────
// Filters, sort, columns, and search live in the hash so a filtered view is
// shareable and survives a reload.

export function encodeState(state) {
  try {
    const json = JSON.stringify(state);
    return btoa(unescape(encodeURIComponent(json)))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  } catch {
    return '';
  }
}

export function decodeState(text) {
  if (!text) return null;
  try {
    const b64 = text.replace(/-/g, '+').replace(/_/g, '/');
    return JSON.parse(decodeURIComponent(escape(atob(b64))));
  } catch {
    return null;
  }
}

export function readHash() {
  const raw = (location.hash || '').replace(/^#/, '');
  const [tab, encoded] = raw.split('?');
  return { tab: tab || 'overview', state: decodeState(encoded) || {} };
}

export function writeHash(tab, state) {
  const meaningful = {};
  if (state.filters && Object.keys(state.filters).length) meaningful.filters = state.filters;
  if (state.search) meaningful.search = state.search;
  if (state.sort) meaningful.sort = state.sort;
  if (state.columns) meaningful.columns = state.columns;
  const encoded = Object.keys(meaningful).length ? `?${encodeState(meaningful)}` : '';
  const next = `#${tab}${encoded}`;
  if (location.hash !== next) history.replaceState(null, '', next);
}

// ── Omnibox ─────────────────────────────────────────────────────────────────
// `env:prod status:200 !cdn_name score>60 -scan_artifact "some title"`
// Produces the same filter objects the API and the CLI consume.

export function parseOmnibox(text, catalog) {
  const filters = {};
  const free = [];
  const tokens = String(text || '').match(/(?:[^\s"]+|"[^"]*")+/g) || [];

  for (const raw of tokens) {
    const token = raw.replace(/^"|"$/g, '');
    if (!token) continue;

    let negate = false;
    let body = token;
    if (body.startsWith('-') && body.length > 1 && !body.includes(':')) {
      negate = true;
      body = body.slice(1);
    }

    const cmp = body.match(/^([A-Za-z_][\w.]*)\s*(>=|<=|>|<)\s*(.+)$/);
    if (cmp && catalog[cmp[1]]) {
      const [, key, op, value] = cmp;
      const existing = filters[key] && typeof filters[key] === 'object'
        && !Array.isArray(filters[key]) ? filters[key] : {};
      if (op === '>' || op === '>=') existing.min = value;
      else existing.max = value;
      filters[key] = existing;
      continue;
    }

    const pair = body.match(/^([A-Za-z_][\w.]*):(.*)$/);
    if (pair && catalog[pair[1]]) {
      const [, key, value] = pair;
      const col = catalog[key];
      const val = value.startsWith('!') ? value : (negate ? `!${value}` : value);
      if (col.is_list) {
        const current = (filters[key] && filters[key].values) || [];
        filters[key] = { values: [...current, value], mode: 'any' };
      } else {
        filters[key] = [...(filters[key] || []), val];
      }
      continue;
    }

    // A bare word matching a boolean column toggles it.
    if (catalog[body] && catalog[body].type === 'bool') {
      filters[body] = [negate ? 'false' : 'true'];
      continue;
    }

    free.push(token);
  }

  return { filters, search: free.join(' ') };
}

export function describeFilters(filters, catalog) {
  const out = [];
  for (const [key, spec] of Object.entries(filters || {})) {
    const label = (catalog[key] && catalog[key].label) || key;
    if (Array.isArray(spec)) {
      out.push({ key, text: `${label}: ${spec.join(' or ')}` });
    } else if (spec && typeof spec === 'object' && 'values' in spec) {
      out.push({ key, text: `${label} ${spec.mode || 'any'}: ${(spec.values || []).join(', ')}` });
    } else if (spec && typeof spec === 'object') {
      const parts = [];
      if (spec.min !== undefined && spec.min !== '') parts.push(`≥ ${spec.min}`);
      if (spec.max !== undefined && spec.max !== '') parts.push(`≤ ${spec.max}`);
      if (parts.length) out.push({ key, text: `${label} ${parts.join(' and ')}` });
    } else if (spec) {
      out.push({ key, text: `${label}: ${spec}` });
    }
  }
  return out;
}

export function downloadText(filename, text, mime = 'text/plain') {
  const blob = new Blob([text], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
