// Data access.
//
// Abstracts live-fetch from an inlined snapshot, so the same view code serves
// both the served app and a future offline single-file export. Pattern taken
// from frogy_web/static/app/orbis.js:20.

import { getStoredKey } from './auth.js';

export const SNAP = (typeof window !== 'undefined' && window.__FROGSCOPE__) || null;

// Every request carries the access key (v2) — there is no session/cookie,
// just this one shared header, checked by server.py's before_request hook.
function authHeaders() {
  const key = getStoredKey();
  return key ? { 'X-Auth-Key': key } : {};
}

// A 401 means the key was rejected — wrong, rotated elsewhere, or never
// set. Rather than every one of the ~30 call sites below handling that,
// this fires one event auth.js's AuthGate listens for and drops straight
// back to the key-entry screen. store.js never imports auth.js's component,
// only its storage helpers, so the data layer stays ignorant of the auth UI.
function _reportUnauthorised() {
  if (typeof window !== 'undefined') {
    window.dispatchEvent(new CustomEvent('frogscope:unauthorised'));
  }
}

// A drop-in replacement for `fetch()` against `/api/*` — same signature,
// same resolved Response, so an existing `fetch(url).then(r => r.json())`
// call site needs only its function name changed, not its shape. Exists
// because several views (exec.js, history.js, risk.js, views.js) call
// `/api/*` directly with raw `fetch()` instead of the jget/jpost/jdel
// wrappers below, for endpoints not yet given a named store.js method —
// every one of those calls silently 401s under the v2 access-key gate
// without this, since plain `fetch()` never attaches the header.
export async function authFetch(path, opts = {}) {
  const res = await fetch(path, {
    ...opts,
    headers: { ...(opts.headers || {}), ...authHeaders() },
  });
  if (res.status === 401) _reportUnauthorised();
  return res;
}

async function jget(path) {
  const res = await fetch(path, { headers: { Accept: 'application/json', ...authHeaders() } });
  const body = await res.json().catch(() => ({}));
  if (res.status === 401) _reportUnauthorised();
  if (!res.ok) throw new Error(body.error || `${res.status} ${path}`);
  return body;
}

async function jpost(path, payload) {
  const res = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json', ...authHeaders() },
    body: JSON.stringify(payload),
  });
  const body = await res.json().catch(() => ({}));
  if (res.status === 401) _reportUnauthorised();
  if (!res.ok) throw new Error(body.error || `${res.status} ${path}`);
  return body;
}

async function jdel(path, payload) {
  const res = await fetch(path, {
    method: 'DELETE',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json', ...authHeaders() },
    body: JSON.stringify(payload || {}),
  });
  const body = await res.json().catch(() => ({}));
  if (res.status === 401) _reportUnauthorised();
  if (!res.ok) throw new Error(body.error || `${res.status} ${path}`);
  return body;
}

async function jpatch(path, payload) {
  const res = await fetch(path, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json', ...authHeaders() },
    body: JSON.stringify(payload || {}),
  });
  const body = await res.json().catch(() => ({}));
  if (res.status === 401) _reportUnauthorised();
  if (!res.ok) throw new Error(body.error || `${res.status} ${path}`);
  return body;
}

function qs(params) {
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(params || {})) {
    if (v !== undefined && v !== null && v !== '') sp.set(k, String(v));
  }
  const s = sp.toString();
  return s ? `?${s}` : '';
}

export const store = {
  async columns(run, project) {
    if (SNAP) return SNAP.columns;
    return jget(`/api/columns${qs({ run, project })}`);
  },

  async runs(project) {
    if (SNAP) return SNAP.runs || [];
    return (await jget(`/api/runs${qs({ project })}`)).runs;
  },

  async projects() {
    if (SNAP) return SNAP.projects || [];
    return (await jget('/api/projects')).projects;
  },

  async summary(run, project) {
    if (SNAP) return SNAP.summary;
    return jget(`/api/summary${qs({ run, project })}`);
  },

  async query(body) {
    if (SNAP) return snapshotQuery(body);
    return jpost('/api/endpoints/query', body);
  },

  async facets(body) {
    if (SNAP) return { facets: SNAP.facets || {} };
    return jpost('/api/endpoints/facets', body);
  },

  async endpoint(key, run, project) {
    if (SNAP) {
      const row = (SNAP.rows || []).find((r) => r.endpoint_key === key);
      return { endpoint: row || {}, same_host: [], same_ip: [] };
    }
    return jget(`/api/endpoints/${encodeURIComponent(key)}${qs({ run, project })}`);
  },

  async hosts(run, project) {
    if (SNAP) return { hosts: SNAP.hosts || [] };
    return jget(`/api/hosts${qs({ run, project })}`);
  },

  async quality(run, project) {
    if (SNAP) return SNAP.quality;
    return jget(`/api/quality${qs({ run, project })}`);
  },

  // ── v2: network & certificate correlation ───────────────────────────────
  // No SNAP branch reads real data yet — the offline single-file export
  // doesn't serialise this data (out of scope for this release, see the
  // README's v2 checklist) — so these degrade to empty rather than throwing,
  // exactly like every other view does when a run never opted into
  // "Correlate assets".
  async network(run, project) {
    if (SNAP) return { correlated: false, collectors: [] };
    return jget(`/api/network/summary${qs({ run, project })}`);
  },

  async networkIps(run, project, page, page_size) {
    if (SNAP) return { rows: [], total: 0 };
    return jget(`/api/network/ips${qs({ run, project, page, page_size })}`);
  },

  async ip(address, run, project) {
    if (SNAP) return { ip: {}, hostnames: [], endpoints: [], certificates: [] };
    return jget(`/api/network/ips/${encodeURIComponent(address)}${qs({ run, project })}`);
  },

  async cidrs(run, project, page, page_size) {
    if (SNAP) return { rows: [], total: 0 };
    return jget(`/api/network/cidrs${qs({ run, project, page, page_size })}`);
  },

  async cidr(block, run, project) {
    if (SNAP) return { cidr: {}, ips: [] };
    return jget(`/api/network/cidrs/${encodeURIComponent(block)}${qs({ run, project })}`);
  },

  async certs(run, project, { status, page, page_size } = {}) {
    if (SNAP) return { rows: [], total: 0 };
    return jget(`/api/certs${qs({ run, project, status, page, page_size })}`);
  },

  async cert(sha256, run, project) {
    if (SNAP) return { certificate: {}, names: [], observations: [] };
    return jget(`/api/certs/${encodeURIComponent(sha256)}${qs({ run, project })}`);
  },

  async discovered(run, project) {
    if (SNAP) return { rows: [] };
    return jget(`/api/network/discovered${qs({ run, project })}`);
  },

  async graph(kind, key, run, project) {
    if (SNAP) return { node: { kind, key }, edges: [], truncated: false };
    return jget(`/api/graph/${kind}/${encodeURIComponent(key)}${qs({ run, project })}`);
  },

  // Same pattern used by every other inventory kind — added so `inventory()`
  // below has a single wrapper to call instead of bypassing this layer with
  // a raw `fetch()`, which is what every one of technology/infrastructure/
  // auth used to do (the SNAP offline export therefore had a hole exactly at
  // those three views).
  async inventory(kind, run, project) {
    if (SNAP) return SNAP.inventory?.[kind] || {};
    return jget(`/api/inventory/${kind}${qs({ run, project })}`);
  },

  exportUrl(body, format) {
    const params = new URLSearchParams({ format });
    if (body.run) params.set('run', body.run);
    if (body.project) params.set('project', body.project);
    if (body.search) params.set('q', body.search);
    if (body.sort) params.set('sort', body.sort);
    if (body.filters && Object.keys(body.filters).length) {
      params.set('filters', JSON.stringify(body.filters));
    }
    if (body.columns) params.set('columns', body.columns.join(','));
    return `/api/endpoints/export?${params}`;
  },

  // Every /api/* route now needs the X-Auth-Key header (v2), and a plain
  // <a href> browser navigation cannot carry a custom header — a download
  // link built from exportUrl()/workbook url would just 401. This fetches
  // with the header attached, then hands the browser a client-side blob URL
  // to save instead, which is the same content with no server URL change.
  async download(url, fallbackFilename) {
    const res = await fetch(url, { headers: authHeaders() });
    if (res.status === 401) _reportUnauthorised();
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      throw new Error(body.error || `${res.status} ${url}`);
    }
    // The server already sets a real filename (the run key) in
    // Content-Disposition — reuse it rather than inventing a generic one.
    const disposition = res.headers.get('Content-Disposition') || '';
    const match = disposition.match(/filename="?([^";]+)"?/);
    const filename = (match && match[1]) || fallbackFilename;

    const blob = await res.blob();
    const objectUrl = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = objectUrl;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(objectUrl);
  },

  async upload(file, { project, label, force, allowIncomplete, allowDrift }) {
    const form = new FormData();
    form.append('file', file);
    if (project) form.append('project', project);
    if (label) form.append('label', label);
    if (force) form.append('force', '1');
    if (allowIncomplete) form.append('allow_incomplete', '1');
    if (allowDrift) form.append('allow_drift', '1');
    const res = await fetch('/api/ingest', { method: 'POST', body: form, headers: authHeaders() });
    const body = await res.json().catch(() => ({}));
    if (res.status === 401) _reportUnauthorised();
    if (!res.ok && res.status !== 202) throw new Error(body.error || `${res.status}`);
    return body;
  },

  async uploadStatus(jobId) {
    return jget(`/api/ingest/${jobId}`);
  },

  // ── Scanning: the only calls that cause outbound traffic ────────────────
  async scanTools() {
    if (SNAP) return { ready: false, tools: {}, options: null };
    return jget('/api/scan/tools');
  },

  async scanStart(body) {
    return jpost('/api/scan', body);
  },

  async scanStatus(jobId) {
    return jget(`/api/scan/${jobId}`);
  },

  async scanApprove(jobId) {
    return jpost(`/api/scan/${jobId}/approve`, {});
  },

  async scanCancel(jobId) {
    return jpost(`/api/scan/${jobId}/cancel`, {});
  },

  async scanList() {
    if (SNAP) return [];
    return (await jget('/api/scan')).scans;
  },

  async createProject({ name, slug }) {
    return jpost('/api/projects', { name, slug });
  },

  // Fetched before a delete is offered, so the confirmation can say what will
  // actually be lost rather than "are you sure?".
  async projectStats(slug) {
    return jget(`/api/projects/${encodeURIComponent(slug)}/stats`);
  },

  // Every delete below sends the confirmation the server demands. The server
  // checks it too — this is a courtesy, not the guard.
  async deleteProject(slug) {
    return jdel(`/api/projects/${encodeURIComponent(slug)}`, { confirm: slug });
  },

  async deleteRun(runId, runKey) {
    return jdel(`/api/runs/${runId}`, { confirm: runKey });
  },

  async resetAll() {
    return jpost('/api/reset', { confirm: 'DELETE EVERYTHING' });
  },

  // v2: requires the CURRENT key (attached automatically like every other
  // call) to reach at all — the server's before_request gate already
  // enforces that, so no separate confirmation payload is needed here.
  async rotateAuthKey() {
    return jpost('/api/auth/rotate', {});
  },

  // ── v2: scheduled scanning ───────────────────────────────────────────────
  async schedules(project) {
    if (SNAP) return [];
    return (await jget(`/api/projects/${encodeURIComponent(project)}/schedules`)).schedules;
  },

  async createSchedule(project, body) {
    return jpost(`/api/projects/${encodeURIComponent(project)}/schedules`, body);
  },

  async updateSchedule(id, fields) {
    return jpatch(`/api/schedules/${id}`, fields);
  },

  async deleteSchedule(id) {
    return jdel(`/api/schedules/${id}`);
  },

  async runScheduleNow(id) {
    return jpost(`/api/schedules/${id}/run-now`, {});
  },
};

// Client-side equivalent of the server query, for the offline export where all
// rows are already in memory.
function snapshotQuery({ filters = {}, search = '', sort, page = 1, page_size = 100 }) {
  let rows = (SNAP.rows || []).slice();

  for (const [key, spec] of Object.entries(filters)) {
    if (spec === undefined || spec === null || spec === '') continue;
    rows = rows.filter((row) => matches(row[key], spec));
  }

  if (search) {
    const needle = search.toLowerCase();
    rows = rows.filter((row) =>
      Object.values(row).some((v) => String(v ?? '').toLowerCase().includes(needle)));
  }

  if (sort) {
    const desc = sort.startsWith('-');
    const key = sort.replace(/^[-+]/, '');
    rows.sort((a, b) => {
      const x = a[key], y = b[key];
      if (x === y) return 0;
      if (x === null || x === undefined) return 1;
      if (y === null || y === undefined) return -1;
      return (typeof x === 'number' ? x - y : String(x).localeCompare(String(y)))
        * (desc ? -1 : 1);
    });
  }

  const total = rows.length;
  const start = (page - 1) * page_size;
  return Promise.resolve({
    rows: rows.slice(start, start + page_size),
    total, page, page_size,
    pages: Math.max(1, Math.ceil(total / page_size)),
    run: SNAP.run,
  });
}

function matches(value, spec) {
  if (Array.isArray(spec)) {
    if (!spec.length) return true;
    return spec.some((s) => matchOne(value, s));
  }
  if (typeof spec === 'object') {
    if ('values' in spec) {
      const list = Array.isArray(value) ? value : [value];
      const want = spec.values || [];
      if (!want.length) return true;
      const has = (t) => list.some((v) => String(v).toLowerCase() === String(t).toLowerCase());
      if (spec.mode === 'all') return want.every(has);
      if (spec.mode === 'none') return !want.some(has);
      return want.some(has);
    }
    const num = Number(value);
    if (spec.min !== undefined && spec.min !== '' && num < Number(spec.min)) return false;
    if (spec.max !== undefined && spec.max !== '' && num > Number(spec.max)) return false;
    return true;
  }
  return matchOne(value, spec);
}

function matchOne(value, spec) {
  const text = String(spec);
  if (text.startsWith('!')) return String(value ?? '') !== text.slice(1);
  if (text.startsWith('~')) {
    return String(value ?? '').toLowerCase().includes(text.slice(1).toLowerCase());
  }
  if (text === 'true') return value === true || value === 1;
  if (text === 'false') return value === false || value === 0;
  if (Array.isArray(value)) {
    return value.some((v) => String(v).toLowerCase() === text.toLowerCase());
  }
  return String(value ?? '') === text;
}
