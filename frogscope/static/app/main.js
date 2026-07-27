// App shell: hash routing, run and project pickers, theme toggle.

import { h, render } from 'preact';
import { useCallback, useEffect, useState } from 'preact/hooks';
import htm from 'htm';
import { store } from './store.js';
import { AuthGate } from './auth.js';
import { readHash, writeHash } from './lib.js';
import { CoverageView, OverviewView, RunsView } from './views.js';
import { FindingsView, MethodologyView } from './risk.js';
import { ExecView } from './exec.js';
import { ChangesView } from './history.js';
import { TechnologyView } from './inventory.js';
import { SetupView } from './manage.js';
import { Help } from './help.js';
import { DiscoveredView } from './discovered.js';

const html = htm.bind(h);

// Set before anything renders, not inside `App`'s own effect — `AuthGate`
// (auth.js) shows the access-key screen *before* `App` ever mounts, so an
// effect living inside `App` never runs while that screen is up and the page
// silently falls back to `:root`'s hardcoded dark tokens (tokens.css) no
// matter what the visitor last chose. `'light'`, not `'dark'`, is the
// fallback for a browser with nothing stored yet.
document.body.dataset.theme = localStorage.getItem('frogscope-theme') || 'light';

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
    tabs: [['exec', 'Overview'], ['technology', 'Software']],
  },
  {
    id: 'fix', label: 'What to fix', simple: true,
    help: 'section.fix',
    tabs: [['findings', 'All issues']],
  },
  {
    id: 'changed', label: 'What changed', simple: true,
    help: 'section.changed',
    tabs: [['changes', 'Since last scan'], ['discovered', 'Newly discovered']],
  },
  {
    id: 'data', label: 'Configuration',
    help: 'section.data',
    tabs: [['runs', 'Scans & projects'], ['coverage', 'What was collected'],
           ['methodology', 'How scoring works']],
  },
];

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
    localStorage.getItem('frogscope-theme') || 'light');
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

  // `/` focuses the omnibox, which is the fastest way into the grid.
  useEffect(() => {
    const onKey = (e) => {
      if (e.key === '/' && !/^(INPUT|SELECT|TEXTAREA)$/.test(e.target.tagName)) {
        e.preventDefault();
        const box = document.querySelector('.omnibox');
        if (box) box.focus();
        else navigate('exec');
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
    body = html`<${ExecView} run=${run} project=${project} catalog=${catalog}
      state=${state} onNavigate=${navigate} />`;
  } else if (tab === 'changes') {
    body = html`<${ChangesView} run=${run} project=${project}
      onNavigate=${navigate} />`;
  } else if (tab === 'discovered') {
    body = html`<${DiscoveredView} run=${run} project=${project}
      onNavigate=${navigate} />`;
  } else if (tab === 'findings') {
    body = html`<${FindingsView} project=${project} onNavigate=${navigate} />`;
  } else if (tab === 'methodology') {
    body = html`<${MethodologyView} run=${run} project=${project} />`;
  } else if (tab === 'technology') {
    body = html`<${TechnologyView} run=${run} project=${project}
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
    body = html`<${ExecView} run=${run} project=${project} catalog=${catalog}
      state=${state} onNavigate=${navigate} />`;
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
