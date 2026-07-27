// Executive view: the scored asset leaderboard, and what the scan could not
// see. The board-pack widgets (posture meters, surface composition, themes,
// zone/environment breakdowns) that used to sit above the table were cut —
// the leaderboard is now the first thing on the page.

import { h } from 'preact';
import { useEffect, useState } from 'preact/hooks';
import htm from 'htm';
import { authFetch } from './store.js';
import { ScopedEndpointsView } from './views.js';

const html = htm.bind(h);

// ── Leaderboard quick-filter categories ─────────────────────────────────────
//
// Moved here from main.js's old standalone Assets tabs — same six category
// definitions (Network/Application/Certificates/On-Prem/Cloud), now driving
// chip buttons above the one big leaderboard table instead of separate tabs.
// Every key list is still `config/columns.yaml`'s own `group:` field for the
// relevant groups, unchanged from the original tabs.

const IDENTITY_ANCHORS = ['endpoint_key', 'host', 'host_display', 'port', 'scheme'];

const NETWORK_KEYS = [...IDENTITY_ANCHORS,
  'host_ip', 'a', 'aaaa', 'cname', 'cname_final', 'ipv6_enabled', 'dns_multi_a',
  'ip_cluster_size', 'resolvers', 'cidr', 'cidr_prefix_len', 'ip_version',
  'ptr_host', 'ptr_missing', 'ptr_mismatch', 'ip_hostname_count',
  'ip_foreign_domain_count', 'in_claimable_range', 'claimable_provider',
  'dangling_a_record', 'scan_artifact'];
const NETWORK_COLUMNS = ['endpoint_key', 'host', 'host_ip', 'ip_version', 'cidr',
  'ptr_host', 'ptr_missing', 'a', 'aaaa', 'cname_final', 'ip_hostname_count',
  'ip_foreign_domain_count', 'dangling_a_record', 'in_claimable_range'];
const NETWORK_FILTERS = { scan_artifact: [false] };

const APPLICATION_KEYS = [...IDENTITY_ANCHORS,
  'port_category', 'env', 'env_source', 'zone', 'registrable_domain',
  'host_depth', 'nonstd_port',
  'response_class', 'status_code', 'status_class', 'title', 'title_class',
  'serves_content', 'scan_artifact', 'cf_alias_port', 'waf_blocked',
  'content_type', 'content_length', 'words', 'lines', 'response_ms',
  'content_sig', 'content_cluster_size',
  'final_url', 'final_host', 'redirect_offsite', 'redirect_chain_len',
  'redirects_to_https', 'no_tls_redirect', 'auth_surface_type',
  'federated_auth', 'remote_access_exposed', 'mgmt_surface',
  'webserver', 'webserver_family', 'webserver_version', 'version_disclosure',
  'tech', 'tech_count', 'cpe_products', 'is_wordpress', 'wp_plugins', 'api_surface',
  'panel_product', 'panel_group', 'panel_exposure', 'panel_confidence',
  'panel_count', 'is_default_page', 'default_page_product', 'disclosure_count',
  'disclosure_worst', 'disclosure_ids', 'fingerprint_count'];
const APPLICATION_COLUMNS = ['endpoint_key', 'host', 'port', 'scheme', 'status_code',
  'title', 'response_class', 'webserver', 'tech', 'tech_count', 'panel_product',
  'is_default_page'];
const APPLICATION_FILTERS = { serves_content: [true], scan_artifact: [false] };

const CERTIFICATE_KEYS = [...IDENTITY_ANCHORS,
  'cert_subject_cn', 'cert_issuer_org', 'cert_not_after', 'cert_days_remaining',
  'cert_age_days', 'cert_expired', 'cert_self_signed', 'cert_mismatched',
  'cert_untrusted', 'cert_wildcard', 'cert_wildcard_scope', 'cert_san_count',
  'cert_foreign_domain_count', 'cert_host_count', 'tls_version', 'tls_cipher',
  'tls_cipher_grade', 'jarm_hash'];
const CERTIFICATE_COLUMNS = ['endpoint_key', 'host', 'cert_subject_cn', 'cert_issuer_org',
  'cert_not_after', 'cert_days_remaining', 'cert_expired', 'cert_self_signed',
  'cert_mismatched', 'cert_wildcard', 'tls_version', 'tls_cipher_grade'];
// Only set when a cert was actually observed for that endpoint — a wide-open
// `min` relies on SQL's NULL handling to drop rows with no certificate at
// all. A `hiddenFilters` value, not `defaultFilters` — never rendered as an
// "Active:" chip.
const CERTIFICATE_FILTERS = { cert_days_remaining: { min: -999999 } };

const HOSTING_KEYS = [...IDENTITY_ANCHORS,
  'host_ip', 'cdn_name', 'cdn_type', 'hosting_provider', 'hosting_kind',
  'edge_provider', 'edge_kind', 'chain_providers', 'origin_exposed', 'no_waf',
  'waf_protected', 'behind_proxy', 'azure_app_proxy', 'origin_health',
  'cf_error_code', 'third_party_dependency', 'defence_layers', 'unprotected'];
const HOSTING_COLUMNS = ['endpoint_key', 'host', 'host_ip', 'hosting_provider',
  'hosting_kind', 'cdn_name', 'edge_provider', 'origin_exposed'];
const CLOUD_KINDS = ['iaas', 'paas', 'saas', 'cdn', 'waf', 'dns', 'storage',
  'app_proxy', 'identity'];
const ONPREM_FILTERS = { hosting_kind: [''] };
const CLOUD_FILTERS = { hosting_kind: CLOUD_KINDS };

// Dropped everywhere for the "All assets" chip — table, Columns picker,
// Facets, omnibox field names — not just hidden from the default view. Not
// scoped narrow enough to be worth its own group; "not required" per direct
// ask.
const EXCLUDED_COLUMNS = ['top_finding', 'worst_severity'];
// Lead with these two (when present) so a risk-sorted table still opens with
// its sort key visible; everything else in the catalog follows in its own
// declared order.
const LEAD_COLUMNS = ['endpoint_key', 'risk_score'];

// `columnKeys: null` tells `scopeCatalog` (views.js) to pass the full,
// unrestricted catalog through — "All" gets every column and every built-in
// preset, exactly like the old standalone "All Assets" tab did. Which
// columns show *by default* is still "everything" per direct ask — computed
// from the live catalog at render time in `Leaderboard`, not a fixed list,
// since the catalog itself is only known once fetched.
const CATEGORIES = [
  { id: 'all', label: 'All assets', columnKeys: null, excludeKeys: EXCLUDED_COLUMNS,
    defaultFilters: {} },
  { id: 'network', label: 'Network', columnKeys: NETWORK_KEYS,
    defaultColumns: NETWORK_COLUMNS, defaultFilters: NETWORK_FILTERS },
  { id: 'application', label: 'Application', columnKeys: APPLICATION_KEYS,
    defaultColumns: APPLICATION_COLUMNS, defaultFilters: APPLICATION_FILTERS },
  { id: 'certificates', label: 'Certificates', columnKeys: CERTIFICATE_KEYS,
    defaultColumns: CERTIFICATE_COLUMNS, hiddenFilters: CERTIFICATE_FILTERS },
  { id: 'onprem', label: 'On-prem', columnKeys: HOSTING_KEYS,
    defaultColumns: HOSTING_COLUMNS, defaultFilters: ONPREM_FILTERS },
  { id: 'cloud', label: 'Cloud', columnKeys: HOSTING_KEYS,
    defaultColumns: HOSTING_COLUMNS, defaultFilters: CLOUD_FILTERS },
];

// Every column the live catalog has, minus `EXCLUDED_COLUMNS`, `LEAD_COLUMNS`
// first. A user who unselects some still gets their own selection back next
// visit via `persistKey` (`ScopedEndpointsView`/`views.js`'s localStorage
// remember-columns feature) — this is only the first-ever default.
function allColumnsDefault(catalog) {
  const keys = (catalog.columns || []).map((c) => c.key)
    .filter((k) => !EXCLUDED_COLUMNS.includes(k));
  const lead = LEAD_COLUMNS.filter((k) => keys.includes(k));
  return [...lead, ...keys.filter((k) => !lead.includes(k))];
}

// The scored asset leaderboard — every endpoint, worst-risk first, with
// quick-filter chips standing in for what used to be five separate Assets
// tabs. Software stays a genuinely different shape of data (grouped by
// product, not one row per endpoint) so its chip links out to the
// Technology page instead of scoping columns here.
//
// `initialFilters` seeds the "All" chip only, and only at mount — a deep
// link (e.g. "Open the affected endpoints") should land pre-filtered, but a
// user's own edits inside the grid afterwards must not be stomped by a stale
// prop on re-render. The caller forces a remount when a fresh deep link
// arrives by keying this component on the filters themselves.
function Leaderboard({ run, project, catalog, initialFilters, onNavigate }) {
  const [activeId, setActiveId] = useState('all');
  const active = CATEGORIES.find((c) => c.id === activeId) || CATEGORIES[0];
  const defaultFilters = activeId === 'all'
    ? (initialFilters || active.defaultFilters) : active.defaultFilters;
  const defaultColumns = activeId === 'all'
    ? allColumnsDefault(catalog) : active.defaultColumns;

  return html`<div class="card no-print-break">
    <h3>All assets, worst risk first</h3>
    <nav class="tabs" aria-label="Filter by category" style="margin-bottom:10px">
      ${CATEGORIES.map((c) => html`
        <button class="tab" aria-current=${c.id === activeId ? 'page' : null}
          onClick=${() => setActiveId(c.id)}>${c.label}</button>`)}
      <button class="tab" onClick=${() => onNavigate('technology')}>Software</button>
    <//>
    <div class="embedded-table">
      <${ScopedEndpointsView} key=${activeId} run=${run} project=${project} catalog=${catalog}
        columnKeys=${active.columnKeys} excludeKeys=${active.excludeKeys}
        defaultColumns=${defaultColumns}
        defaultFilters=${defaultFilters} hiddenFilters=${active.hiddenFilters}
        defaultSort="-risk_score" persistKey=${`leaderboard:${activeId}`} />
    </div>
  </div>`;
}

export function ExecView({ run, project, catalog, state, onNavigate }) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    setData(null);
    setError(null);
    const q = new URLSearchParams();
    if (run) q.set('run', run);
    if (project) q.set('project', project);
    authFetch(`/api/exec?${q}`)
      .then((r) => r.json())
      .then((d) => (d.error ? setError(d.error) : setData(d)))
      .catch((e) => setError(e.message));
  }, [run, project]);

  if (error) {
    return html`<div class="view-scroll"><div class="empty">
      <h2>Nothing to report yet</h2>
      <p class="muted">${error}</p>
      <button class="btn btn-primary" onClick=${() => onNavigate('runs')}>
        Upload a scan</button>
    </div></div>`;
  }
  if (!data) return html`<div class="loading">Loading…</div>`;

  return html`<div class="view-scroll exec">
    ${catalog ? html`<${Leaderboard} key=${JSON.stringify((state && state.filters) || {})}
      run=${run} project=${project} catalog=${catalog}
      initialFilters=${state && state.filters} onNavigate=${onNavigate} />` : null}

    <${Caveats} caveats=${data.caveats} onNavigate=${onNavigate} />
  </div>`;
}

// ── Caveats ─────────────────────────────────────────────────────────────────

function Caveats({ caveats, onNavigate }) {
  return html`<div class="card no-print-break">
    <h3>What this scan could not see</h3>
    <ul style="margin:0;padding-left:18px">
      ${caveats.map((caveat) => html`<li style="margin-bottom:4px">${caveat}</li>`)}
    </ul>
    <div class="no-print" style="margin-top:10px;display:flex;gap:8px;flex-wrap:wrap">
      <button class="btn btn-sm" onClick=${() => onNavigate('coverage')}>
        Coverage detail</button>
      <button class="btn btn-sm" onClick=${() => onNavigate('methodology')}>
        How scoring works</button>
    </div>
  </div>`;
}
