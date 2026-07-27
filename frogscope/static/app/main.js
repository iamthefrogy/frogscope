// App shell: hash routing, run and project pickers, theme toggle.

import { h, render } from 'preact';
import { useCallback, useEffect, useState } from 'preact/hooks';
import htm from 'htm';
import { store } from './store.js';
import { AuthGate } from './auth.js';
import { readHash, writeHash } from './lib.js';
import { CoverageView, EndpointsView, OverviewView, RunsView, ScopedEndpointsView } from './views.js';
import { FindingsView, MethodologyView } from './risk.js';
import { ExecView } from './exec.js';
import { ChangesView, TrendsView } from './history.js';
import { AuthView, TechnologyView } from './inventory.js';
import { SetupView } from './manage.js';
import { Help } from './help.js';
import { CertificatesView } from './certs.js';
import { DiscoveredView } from './discovered.js';

const html = htm.bind(h);

// Five plain-language sections instead of fourteen equal tabs.
//
// The old bar asked the reader to understand the whole tool before clicking
// anything, and an executive has no way to tell "Infra" from "Coverage" from
// "Method". These names are questions somebody actually arrives with.
//
// `simple: true` marks the sections a non-technical reader needs. The rest stay
// one click away rather than being removed — depth is the point of the tool.
const SECTIONS = [
  {
    id: 'summary', label: 'Summary', simple: true,
    help: 'section.summary',
    tabs: [['exec', 'Overview']],
  },
  {
    id: 'fix', label: 'What to fix', simple: true,
    help: 'section.fix',
    tabs: [['findings', 'All issues'], ['certificates', 'Certificates'],
           ['auth', 'Login pages']],
  },
  {
    id: 'changed', label: 'What changed', simple: true,
    help: 'section.changed',
    tabs: [['changes', 'Since last scan'], ['trends', 'Over time'],
           ['discovered', 'Newly discovered']],
  },
  {
    id: 'assets', label: 'Assets',
    help: 'section.assets',
    tabs: [['endpoints', 'All Assets'], ['technology', 'Software'],
           ['network', 'Network'], ['application', 'Application'],
           ['assets-certs', 'Certificates'], ['onprem', 'On-Prem'], ['cloud', 'Cloud']],
  },
  {
    id: 'data', label: 'Data & setup',
    help: 'section.data',
    tabs: [['runs', 'Scans & projects'], ['coverage', 'What was collected'],
           ['methodology', 'How scoring works']],
  },
];

// Each scoped Assets tab is "All Assets" (the master table, via
// `ScopedEndpointsView`) pre-scoped three ways: which columns are AVAILABLE
// at all (`*_KEYS` — Facets, the omnibox, and the Columns picker only ever
// offer these), which of those show by DEFAULT (`*_COLUMNS`, a subset of the
// keys), and — for tabs where a category boundary actually exists in the
// data — which ROWS count as that category (`*_FILTERS`). Every key list is
// `config/columns.yaml`'s own `group:` field for the relevant groups, so
// "relevant" here means the same grouping the column registry already uses,
// not a new taxonomy invented in the frontend.

const IDENTITY_ANCHORS = ['endpoint_key', 'host', 'host_display', 'port', 'scheme'];

// `network` + `dns` groups, minus the cert_* fields that live in the same
// `network` group (those belong to Certificates instead). Plus
// `scan_artifact` (a `response`-group field) — NETWORK_FILTERS below filters
// on it, and it must appear here too or the Facets/chip/omnibox surface
// can't resolve it against the scoped catalog (shows the raw field name
// instead of its label).
const NETWORK_KEYS = [...IDENTITY_ANCHORS,
  'host_ip', 'a', 'aaaa', 'cname', 'cname_final', 'ipv6_enabled', 'dns_multi_a',
  'ip_cluster_size', 'resolvers', 'cidr', 'cidr_prefix_len', 'ip_version',
  'ptr_host', 'ptr_missing', 'ptr_mismatch', 'ip_hostname_count',
  'ip_foreign_domain_count', 'in_claimable_range', 'claimable_provider',
  'dangling_a_record', 'scan_artifact'];
const NETWORK_COLUMNS = ['endpoint_key', 'host', 'host_ip', 'ip_version', 'cidr',
  'ptr_host', 'ptr_missing', 'a', 'aaaa', 'cname_final', 'ip_hostname_count',
  'ip_foreign_domain_count', 'dangling_a_record', 'in_claimable_range'];
// Scan artefacts (a TLS-only port probed over cleartext, etc.) are probe
// noise, not real network assets — everything else stays, including dead or
// dangling hosts, since those are exactly what a network view needs to show.
const NETWORK_FILTERS = { scan_artifact: [false] };

// `identity` + `response` + `redirect` + `fingerprint` + `exposure` groups —
// the runtime/application side of an endpoint, as opposed to its network or
// certificate identity.
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
// "Applications" means things actually serving real content — scan
// artefacts, dead ports, and WAF blocks are noise for this view even though
// they're still legitimate rows in All Assets.
const APPLICATION_FILTERS = { serves_content: [true], scan_artifact: [false] };

// The cert_* subset of the `network` group (see NETWORK_KEYS above).
const CERTIFICATE_KEYS = [...IDENTITY_ANCHORS,
  'cert_subject_cn', 'cert_issuer_org', 'cert_not_after', 'cert_days_remaining',
  'cert_age_days', 'cert_expired', 'cert_self_signed', 'cert_mismatched',
  'cert_untrusted', 'cert_wildcard', 'cert_wildcard_scope', 'cert_san_count',
  'cert_foreign_domain_count', 'cert_host_count', 'tls_version', 'tls_cipher',
  'tls_cipher_grade', 'jarm_hash'];
const CERTIFICATE_COLUMNS = ['endpoint_key', 'host', 'cert_subject_cn', 'cert_issuer_org',
  'cert_not_after', 'cert_days_remaining', 'cert_expired', 'cert_self_signed',
  'cert_mismatched', 'cert_wildcard', 'tls_version', 'tls_cipher_grade'];
// `cert_days_remaining` is only ever set when a cert was actually observed
// for that endpoint (`ingest/correlate.py::attach`) — null otherwise. A
// wide-open `min` range excludes nothing real but relies on SQL's NULL
// handling to drop every row with no certificate at all, which is exactly
// "relevant assets" for this tab: something that actually presented a cert.
// A `hiddenFilters` value, not `defaultFilters` — this is a NULL-exclusion
// trick, not a real user-facing threshold, so it must never render as an
// "Active:" chip or a pre-filled "Days to expiry ≥ -999999" box on the
// grid's own column filter (see `ScopedEndpointsView`/`EndpointsView`).
const CERTIFICATE_FILTERS = { cert_days_remaining: { min: -999999 } };

// `infra` group, plus the one DNS field (`host_ip`) needed to make sense of it.
const HOSTING_KEYS = [...IDENTITY_ANCHORS,
  'host_ip', 'cdn_name', 'cdn_type', 'hosting_provider', 'hosting_kind',
  'edge_provider', 'edge_kind', 'chain_providers', 'origin_exposed', 'no_waf',
  'waf_protected', 'behind_proxy', 'azure_app_proxy', 'origin_health',
  'cf_error_code', 'third_party_dependency', 'defence_layers', 'unprotected'];
const HOSTING_COLUMNS = ['endpoint_key', 'host', 'host_ip', 'hosting_provider',
  'hosting_kind', 'cdn_name', 'edge_provider', 'origin_exposed'];
// `hosting_kind` is set from `classify.hosting_provider()`'s CNAME-chain match
// (`frogscope/ingest/classify.py`) — empty means nothing in the chain matched
// a known cloud/CDN/SaaS/PaaS/IaaS provider. An inferred proxy, not a
// dedicated on-prem field.
const CLOUD_KINDS = ['iaas', 'paas', 'saas', 'cdn', 'waf', 'dns', 'storage',
  'app_proxy', 'identity'];
const ONPREM_FILTERS = { hosting_kind: [''] };
const CLOUD_FILTERS = { hosting_kind: CLOUD_KINDS };

const TAB_TO_SECTION = {};
for (const section of SECTIONS) {
  for (const [tabId] of section.tabs) TAB_TO_SECTION[tabId] = section.id;
}
const ALL_TAB_IDS = Object.keys(TAB_TO_SECTION);

function sectionOf(tab) {
  return TAB_TO_SECTION[tab] || 'summary';
}

/** Bare chrome for the setup screen: no tabs, because none of them work yet. */
function Shell({ theme, setTheme, children }) {
  return html`<div class="app">
    <header class="topbar">
      <div class="brand">
        <span class="brand-dot"></span>
        <div class="brand-text">
          <span class="brand-title">Frogscope</span>
          <span class="brand-sub">An honest map of your internet-facing estate, and what changed since last time</span>
        </div>
      </div>
      <span class="spacer"></span>
      <button class="btn btn-sm" title="Toggle light and dark"
        onClick=${() => setTheme(theme === 'dark' ? 'light' : 'dark')}>
        ${theme === 'dark' ? '☾' : '☀'}
      </button>
    </header>
    <div class="main">${children}</div>
  </div>`;
}

function App() {
  const initial = readHash();
  const [tab, setTab] = useState(initial.tab);
  const [state, setState] = useState(initial.state);
  const [catalog, setCatalog] = useState(null);
  const [runs, setRuns] = useState(null);
  const [projects, setProjects] = useState([]);
  const [project, setProject] = useState('');
  const run = 'latest';
  const [theme, setTheme] = useState(
    localStorage.getItem('frogscope-theme') || 'dark');
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    document.body.dataset.theme = theme;
    localStorage.setItem('frogscope-theme', theme);
  }, [theme]);

  useEffect(() => {
    const onHash = () => {
      const next = readHash();
      setTab(next.tab);
      setState(next.state);
    };
    window.addEventListener('hashchange', onHash);
    return () => window.removeEventListener('hashchange', onHash);
  }, []);

  useEffect(() => {
    store.projects().then((list) => {
      setProjects(list);
      // Also re-point when the selected project has just been deleted, or the
      // app keeps querying a slug the server no longer knows.
      const stillThere = list.some((p) => p.slug === project);
      if (!stillThere) setProject(list.length ? list[0].slug : '');
    }).catch(() => setProjects([]));
  }, [reloadKey]);

  useEffect(() => {
    store.runs(project || undefined).then(setRuns).catch(() => setRuns([]));
  }, [project, reloadKey]);

  useEffect(() => {
    store.columns(run, project || undefined)
      .then(setCatalog)
      .catch(() => setCatalog({ columns: [], groups: {}, default_visible: [] }));
  }, [run, project, reloadKey]);

  useEffect(() => { writeHash(tab, state); }, [tab, state]);

  const navigate = useCallback((nextTab, nextState) => {
    setTab(nextTab);
    if (nextState) setState((prev) => ({ ...prev, ...nextState, page: 1 }));
  }, []);

  const patchState = useCallback((patch) => {
    setState((prev) => ({ ...prev, ...patch }));
  }, []);

  // `/` focuses the omnibox, which is the fastest way into the grid.
  useEffect(() => {
    const onKey = (e) => {
      if (e.key === '/' && !/^(INPUT|SELECT|TEXTAREA)$/.test(e.target.tagName)) {
        e.preventDefault();
        const box = document.querySelector('.omnibox');
        if (box) box.focus();
        else navigate('endpoints');
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [navigate]);

  if (!catalog) return html`<div class="loading">Loading…</div>`;

  const hasRuns = runs && runs.length > 0;

  const reload = () => setReloadKey((n) => n + 1);
  const activeSection = sectionOf(tab);
  const currentSection = SECTIONS.find((s) => s.id === activeSection);

  // Nothing ingested anywhere: the only useful screen is the one that gets a
  // scan in. Showing fourteen empty tabs instead is how a tool feels broken on
  // first contact.
  //
  // With no projects at all the gate ignores the current tab, because deleting
  // the last project leaves you sitting on Runs with fourteen tabs that have
  // nothing behind them.
  const anyRuns = projects.some((p) => p.run_count > 0);
  if (!projects.length || (!anyRuns && tab !== 'runs')) {
    return html`<${Shell} theme=${theme} setTheme=${setTheme}>
      <${SetupView} projects=${projects} project=${project}
        onSelect=${setProject}
        onCreated=${(made) => { reload(); setProject(made.slug); }}
        onDeleted=${reload}
        onIngested=${() => { reload(); setTab('exec'); }} />
    <//>`;
  }

  let body;
  if (!hasRuns && tab !== 'runs') {
    body = html`<div class="view-scroll"><div class="empty">
      <h2>Nothing in this project yet</h2>
      <p class="muted">Other projects have scans, but
        <strong>${project}</strong> does not.</p>
      <button class="btn btn-primary" onClick=${() => navigate('runs')}>
        Add a scan</button>
    </div></div>`;
  } else if (tab === 'exec') {
    body = html`<${ExecView} run=${run} project=${project} onNavigate=${navigate} />`;
  } else if (tab === 'endpoints') {
    body = html`<${EndpointsView} run=${run} project=${project} catalog=${catalog}
      state=${state} onState=${patchState} />`;
  } else if (tab === 'network') {
    body = html`<${ScopedEndpointsView} key="network" run=${run} project=${project} catalog=${catalog}
      columnKeys=${NETWORK_KEYS} defaultColumns=${NETWORK_COLUMNS}
      defaultFilters=${NETWORK_FILTERS} />`;
  } else if (tab === 'application') {
    body = html`<${ScopedEndpointsView} key="application" run=${run} project=${project} catalog=${catalog}
      columnKeys=${APPLICATION_KEYS} defaultColumns=${APPLICATION_COLUMNS}
      defaultFilters=${APPLICATION_FILTERS} />`;
  } else if (tab === 'assets-certs') {
    body = html`<${ScopedEndpointsView} key="assets-certs" run=${run} project=${project} catalog=${catalog}
      columnKeys=${CERTIFICATE_KEYS} defaultColumns=${CERTIFICATE_COLUMNS}
      hiddenFilters=${CERTIFICATE_FILTERS} />`;
  } else if (tab === 'onprem') {
    body = html`<${ScopedEndpointsView} key="onprem" run=${run} project=${project} catalog=${catalog}
      columnKeys=${HOSTING_KEYS} defaultColumns=${HOSTING_COLUMNS}
      defaultFilters=${ONPREM_FILTERS} />`;
  } else if (tab === 'cloud') {
    body = html`<${ScopedEndpointsView} key="cloud" run=${run} project=${project} catalog=${catalog}
      columnKeys=${HOSTING_KEYS} defaultColumns=${HOSTING_COLUMNS}
      defaultFilters=${CLOUD_FILTERS} />`;
  } else if (tab === 'changes') {
    body = html`<${ChangesView} run=${run} project=${project}
      onNavigate=${navigate} />`;
  } else if (tab === 'trends') {
    body = html`<${TrendsView} project=${project} onNavigate=${navigate} />`;
  } else if (tab === 'discovered') {
    body = html`<${DiscoveredView} run=${run} project=${project}
      onNavigate=${navigate} />`;
  } else if (tab === 'findings') {
    body = html`<${FindingsView} project=${project} onNavigate=${navigate} />`;
  } else if (tab === 'certificates') {
    body = html`<${CertificatesView} run=${run} project=${project}
      onNavigate=${navigate} />`;
  } else if (tab === 'methodology') {
    body = html`<${MethodologyView} run=${run} project=${project} />`;
  } else if (tab === 'technology') {
    body = html`<${TechnologyView} run=${run} project=${project}
      onNavigate=${navigate} />`;
  } else if (tab === 'auth') {
    body = html`<${AuthView} run=${run} project=${project}
      onNavigate=${navigate} />`;
  } else if (tab === 'coverage') {
    body = html`<${CoverageView} run=${run} project=${project} />`;
  } else if (tab === 'runs') {
    body = html`<${RunsView} projects=${projects} project=${project}
      onSelect=${setProject} onProjectsChanged=${reload}
      onIngested=${reload} />`;
  } else if (tab === 'overview') {
    body = html`<${OverviewView} run=${run} project=${project} onNavigate=${navigate} />`;
  } else {
    body = html`<${ExecView} run=${run} project=${project} onNavigate=${navigate} />`;
  }

  return html`<div class="app">
    <header class="topbar">
      <div class="brand">
        <span class="brand-dot"></span>
        <div class="brand-text">
          <span class="brand-title">Frogscope</span>
          <span class="brand-sub">An honest map of your internet-facing estate, and what changed since last time</span>
        </div>
      </div>

      <nav class="tabs" aria-label="Sections">
        ${SECTIONS.map((section) => html`
          <button class="tab"
            aria-current=${activeSection === section.id ? 'page' : null}
            onClick=${() => navigate(section.tabs[0][0])}>${section.label}</button>`)}
      </nav>

      <span class="spacer"></span>

      ${projects.length > 0 && html`
        <select class="input" value=${project} title="Project"
          onChange=${(e) => {
            if (e.target.value === '__manage') { navigate('runs'); return; }
            setProject(e.target.value);
          }}>
          ${projects.map((p) => html`
            <option value=${p.slug}>${p.name}</option>`)}
          <option value="__manage">+ New project / manage…</option>
        </select>`}

      <button class="btn btn-sm" title="Toggle light and dark"
        onClick=${() => setTheme(theme === 'dark' ? 'light' : 'dark')}>
        ${theme === 'dark' ? '☾' : '☀'}
      </button>
    </header>

    ${currentSection && currentSection.tabs.length > 1 ? html`
      <nav class="subnav" aria-label=${currentSection.label}>
        <span class="subnav-label">${currentSection.label}</span>
        ${currentSection.tabs.map(([id, label]) => html`
          <button class="tab" aria-current=${tab === id ? 'page' : null}
            onClick=${() => navigate(id)}>${label}</button>`)}
        <${Help} topic=${currentSection.help} />
      </nav>` : null}

    <div class="main">${body}</div>
  </div>`;
}

render(html`<${AuthGate}><${App} /></${AuthGate}>`, document.getElementById('root'));
