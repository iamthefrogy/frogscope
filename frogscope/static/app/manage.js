// Setup, upload, and deleting things.
//
// Split out of views.js because these are the only screens that WRITE. Everything
// else in the app reads, and keeping the destructive paths in one file makes them
// easy to find and to reason about.

import { h } from 'preact';
import { useEffect, useState } from 'preact/hooks';
import htm from 'htm';
import { SNAP, store } from './store.js';
import { num, when } from './lib.js';
import { CardTitle } from './help.js';
import { ScanPanel } from './scan.js';
import { setStoredKey } from './auth.js';

const html = htm.bind(h);

const RESET_PHRASE = 'DELETE EVERYTHING';

// ── Choosing or creating a project ──────────────────────────────────────────

export function ProjectChooser({ projects, value, onSelect, onCreated,
                                 onDeleted, autoFocus }) {
  // Open by default when there is nothing to pick from — with no projects, the
  // dropdown would be an empty control asking the user to choose from nothing.
  const [creating, setCreating] = useState(!projects.length);
  const [removing, setRemoving] = useState('');
  const [name, setName] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => { if (!projects.length) setCreating(true); }, [projects.length]);

  const create = async () => {
    const trimmed = name.trim();
    if (!trimmed) { setError('Give the project a name first.'); return; }
    setBusy(true); setError('');
    try {
      const made = await store.createProject({ name: trimmed });
      setName('');
      setCreating(false);
      onCreated && onCreated(made);
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  if (creating) {
    return html`<div>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <input class="input" style="flex:1;min-width:220px" autofocus=${autoFocus}
          placeholder="Project name, e.g. Acme Corp" value=${name}
          onInput=${(e) => setName(e.target.value)}
          onKeyDown=${(e) => e.key === 'Enter' && create()} />
        <button class="btn btn-primary" disabled=${busy} onClick=${create}>
          ${busy ? 'Creating…' : 'Create project'}
        </button>
        ${projects.length > 0 && html`
          <button class="btn" onClick=${() => { setCreating(false); setError(''); }}>
            Cancel
          </button>`}
      </div>
      <p class="subtle" style="margin:6px 0 0">
        A project keeps one target's scans together. Diffs and trends never cross
        between projects, so a client engagement cannot contaminate your own
        estate's history.
      </p>
      ${error && html`<div class="banner error" style="margin-top:10px">
        <span>✕</span><div>${error}</div></div>`}
    </div>`;
  }

  const current = projects.find((p) => p.slug === value);

  return html`<div>
    <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
      <select class="input" value=${value}
        onChange=${(e) => onSelect(e.target.value)}>
        ${projects.map((p) => html`<option value=${p.slug}>
          ${p.name}${' '}(${p.run_count} ${p.run_count === 1 ? 'scan' : 'scans'})
        </option>`)}
      </select>
      <button class="btn" onClick=${() => setCreating(true)}>+ New project</button>
      ${current && html`<button class="btn btn-danger"
        onClick=${() => setRemoving(current.slug)}>
        Delete ${current.name}
      </button>`}
    </div>
    ${removing && html`<${ConfirmProjectDelete} slug=${removing}
      name=${(projects.find((p) => p.slug === removing) || {}).name || removing}
      onCancel=${() => setRemoving('')}
      onDone=${() => { setRemoving(''); onDeleted && onDeleted(); }} />`}
  </div>`;
}


/** Typed confirmation for removing one project and everything in it. */
function ConfirmProjectDelete({ slug, name, onCancel, onDone }) {
  const [stats, setStats] = useState(null);
  const [typed, setTyped] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    setStats(null);
    store.projectStats(slug).then(setStats).catch(() => setStats(null));
  }, [slug]);

  const go = async () => {
    setBusy(true);
    setError('');
    try {
      await store.deleteProject(slug);
      onDone();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  const s = stats && stats.stats;
  return html`<div class="banner" style="margin:10px 0 0">
    <span>▲</span><div>
      <strong>Delete “${name}” and everything in it?</strong>
      ${s ? html`<div style="margin-top:4px">
        This removes ${num(s.runs)} ${s.runs === 1 ? 'scan' : 'scans'},${' '}
        ${num(s.endpoints)} endpoint records, ${num(s.findings)} findings,${' '}
        ${num(s.changes)} recorded changes, ${num(s.saved_views)} saved views, and
        the archived source files.
      </div>` : html`<div class="subtle" style="margin-top:4px">Counting…</div>`}
      <div style="margin-top:4px">
        The project itself goes too, and none of it can be undone. Export first if
        you might want the data.
      </div>
      <div style="display:flex;gap:8px;margin-top:10px;flex-wrap:wrap">
        <input class="input" style="min-width:220px" autofocus
          placeholder=${`Type ${slug} to confirm`} value=${typed}
          onInput=${(e) => setTyped(e.target.value)}
          onKeyDown=${(e) => e.key === 'Enter' && typed === slug && go()} />
        <button class="btn btn-danger" disabled=${busy || typed !== slug}
          onClick=${go}>${busy ? 'Deleting…' : 'Delete permanently'}</button>
        <button class="btn" onClick=${onCancel}>Cancel</button>
      </div>
      ${error && html`<div style="margin-top:8px;color:var(--color-danger)">
        ${error}</div>`}
    </div></div>`;
}

// ── Uploading ───────────────────────────────────────────────────────────────

export function Uploader({ project, onIngested, compact }) {
  const [job, setJob] = useState(null);
  const [over, setOver] = useState(false);
  const [label, setLabel] = useState('');
  const [allowIncomplete, setAllowIncomplete] = useState(false);
  const [allowDrift, setAllowDrift] = useState(false);
  const [force, setForce] = useState(false);
  // Kept so a rejected upload can be retried with an override in one click. The
  // old flow told the user to "drop the file again", which is busywork and — when
  // the offered override was the wrong one — an instruction that never worked.
  const [pending, setPending] = useState(null);

  const send = async (file, overrides) => {
    if (!project) {
      setJob({ state: 'error', message: 'Choose a project first.' });
      return;
    }
    setPending(file);
    const opts = {
      project,
      label: label || undefined,
      force,
      allowIncomplete,
      allowDrift,
      ...(overrides || {}),
    };
    setJob({ state: 'running', step: 'uploading', filename: file.name });
    try {
      const started = await store.upload(file, opts);
      if (!started.job_id) { setJob(started); return; }
      const poll = setInterval(async () => {
        let status;
        try {
          status = await store.uploadStatus(started.job_id);
        } catch (e) {
          clearInterval(poll);
          setJob({ state: 'error', message: e.message });
          return;
        }
        setJob(status);
        if (status.state !== 'running') {
          clearInterval(poll);
          if (status.state === 'done') onIngested && onIngested(status);
        }
      }, 700);
    } catch (e) {
      setJob({ state: 'error', message: e.message });
    }
  };

  // Turn on whichever override the server asked for and immediately retry the
  // file we still hold, rather than asking the user to find it again.
  const retryWith = (overrideName) => {
    const overrides = {};
    if (overrideName === 'allow_drift') {
      setAllowDrift(true);
      overrides.allowDrift = true;
    } else if (overrideName === 'force') {
      setForce(true);
      overrides.force = true;
    } else {
      setAllowIncomplete(true);
      overrides.allowIncomplete = true;
    }
    if (pending) send(pending, overrides);
  };

  return html`<div>
    <div class=${`dropzone ${over ? 'over' : ''}`}
      onDragOver=${(e) => { e.preventDefault(); setOver(true); }}
      onDragLeave=${() => setOver(false)}
      onDrop=${(e) => {
        e.preventDefault(); setOver(false);
        const file = e.dataTransfer.files && e.dataTransfer.files[0];
        if (file) send(file);
      }}>
      <div style="font-size:22px">⇪</div>
      <div><strong>Drop an httpx output file here</strong></div>
      <div class="subtle">CSV, TSV, JSON, JSONL, or .csv.gz</div>
      <label class="btn" style="margin-top:8px">
        Choose a file
        <input type="file" style="display:none"
          accept=".csv,.tsv,.json,.jsonl,.gz"
          onChange=${(e) => e.target.files[0] && send(e.target.files[0])} />
      </label>
    </div>

    <div style="display:flex;gap:12px;align-items:center;margin-top:12px;flex-wrap:wrap">
      <input class="input" style="min-width:240px"
        placeholder="Label this scan, e.g. 2026-07 monthly"
        value=${label} onInput=${(e) => setLabel(e.target.value)} />
      ${!compact && html`
        <label class="facet-row" style="width:auto">
          <input type="checkbox" checked=${allowIncomplete}
            onChange=${(e) => setAllowIncomplete(e.target.checked)} />
          <span class="label">Accept an unfinished scan</span>
        </label>
        <label class="facet-row" style="width:auto">
          <input type="checkbox" checked=${allowDrift}
            onChange=${(e) => setAllowDrift(e.target.checked)} />
          <span class="label">Accept a big change in size</span>
        </label>
        <label class="facet-row" style="width:auto">
          <input type="checkbox" checked=${force}
            onChange=${(e) => setForce(e.target.checked)} />
          <span class="label">Re-ingest a duplicate</span>
        </label>`}
    </div>

    ${job ? html`<${JobStatus} job=${job} onRetry=${retryWith}
      canRetry=${Boolean(pending)} />` : null}
  </div>`;
}


// What each override is called in plain words, and what accepting it means. The
// server names the override; this only decides how to say it.
const OVERRIDE_LABELS = {
  allow_incomplete: {
    button: 'Accept the unfinished scan and continue',
    caveat: 'A truncated scan has fewer findings, so later trend charts will '
      + 'show it as an improvement that did not happen.',
  },
  allow_drift: {
    button: 'Accept the size change and continue',
    caveat: 'If the scan really did shrink, accepting is correct. If it was cut '
      + 'short, the missing endpoints will read as issues that got fixed.',
  },
  force: {
    button: 'Store it again anyway',
    caveat: 'The duplicate is kept out of the trend line so it cannot count twice.',
  },
};

export function JobStatus({ job, onRetry, canRetry }) {
  if (job.state === 'running') {
    return html`<div class="banner info" style="margin-top:12px">
      <span>⧗</span><div>Reading ${job.filename || ''}…${' '}${job.step || ''}</div>
    </div>`;
  }

  if (job.state === 'duplicate' || job.state === 'incomplete') {
    // `override` comes from the server. Guessing it here is what produced a
    // button that could never work: a size-change rejection was offered the
    // unfinished-scan override, which does not ungate it.
    const which = job.override
      || (job.state === 'duplicate' ? 'force' : 'allow_incomplete');
    const copy = OVERRIDE_LABELS[which] || OVERRIDE_LABELS.allow_incomplete;
    const heading = job.state === 'duplicate'
      ? 'This file has already been ingested.'
      : 'This scan does not look complete.';

    return html`<div class="banner" style="margin-top:12px">
      <span>▲</span><div>
        <strong>${heading}</strong>${' '}${job.message}
        ${(job.warnings || []).map((w) => html`<div class="subtle">${w}</div>`)}
        <div style="margin-top:6px">${copy.caveat}</div>
        ${canRetry
          ? html`<div style="margin-top:8px">
              <button class="btn btn-sm" onClick=${() => onRetry(which)}>
                ${copy.button}
              </button></div>`
          : html`<div class="subtle" style="margin-top:6px">
              Drop the file again to retry.</div>`}
      </div></div>`;
  }

  if (job.state === 'error') {
    return html`<div class="banner error" style="margin-top:12px">
      <span>✕</span><div>${job.message}</div></div>`;
  }

  const s = job.summary || {};
  return html`<div class="banner info" style="margin-top:12px">
    <span>✓</span>
    <div>
      <strong>Ingested as ${job.run_key}.</strong>${' '}
      ${num(job.row_count)} source rows became ${num(job.endpoint_count)}
      ${' '}endpoints across ${num(job.host_count)} hosts.
      ${s.real_endpoints !== undefined ? html`<div style="margin-top:4px">
        ${num(s.real_endpoints)} are real services —${' '}
        ${num(s.scan_artifacts)} scan artefacts and${' '}
        ${num(s.cf_alias_ports)} proxy alias ports were set aside, because
        counting them as separate surface inflates the estate several times over.
      </div>` : null}
      ${(job.warnings || []).map((w) => html`<div class="subtle">▲ ${w}</div>`)}
    </div></div>`;
}

// ── First run ───────────────────────────────────────────────────────────────

export function SetupView({ projects, project, onSelect, onCreated, onIngested,
                            onDeleted }) {
  const hasProject = Boolean(project);
  const [tools, setTools] = useState(null);

  useEffect(() => {
    if (SNAP) return;
    store.scanTools().then(setTools).catch(() => setTools({ ready: false }));
  }, []);

  return html`<div class="view-scroll">
    <div class="setup-head">
      <h1>Get started</h1>
      <p class="muted">Name what you are looking at, then scan it. Everything is
        stored on this machine, and the analysis never touches the network.</p>
    </div>

    <div class="card" style="margin-bottom:16px">
      <${CardTitle} topic="runs.projects">Step 1 — name what you are scanning<//>
      <${ProjectChooser} projects=${projects} value=${project}
        onSelect=${onSelect} onCreated=${onCreated} onDeleted=${onDeleted}
        autoFocus=${true} />
    </div>

    <h2 class="setup-step2">Step 2 — scan it</h2>
    ${!hasProject && html`<p class="subtle" style="margin:0 0 12px">
      Name a project above first — a scan has to belong to something.</p>`}

    <div class="setup-options"
      style=${hasProject ? '' : 'opacity:0.45;pointer-events:none'}>
      <div class="card setup-option">
        ${tools && !tools.ready
          ? html`<div class="banner" style="margin-bottom:0"><span>▲</span><div>
              <strong>The scanners are not installed here.</strong>
              ${Object.values(tools.tools || {}).filter((t) => !t.available)
                .map((t) => html`<div style="margin-top:6px">
                  <code>${t.name}</code> — ${t.purpose}<br/>
                  <span class="subtle">${t.install_hint}</span></div>`)}
              <div style="margin-top:8px">The Docker image bundles all of them:${' '}
                <code>docker compose up</code>.</div>
            </div></div>`
          : html`<${ScanPanel} project=${project} onIngested=${onIngested}
              embedded=${true} />`}
      </div>
    </div>
  </div>`;
}

// ── Deleting things ─────────────────────────────────────────────────────────

export function DangerZone({ onChanged }) {
  // Meaningless in the offline export: `fetch` is shimmed there, so a delete
  // button would look live and silently do nothing.
  if (SNAP) return null;

  return html`<div class="card danger-zone" style="margin-top:16px">
    <${CardTitle} topic="runs.delete">Delete everything<//>
    <p class="subtle" style="margin:0 0 4px">
      To remove a single project, use the <strong>Delete</strong> button beside the
      project selector at the top of this page. This section empties the whole
      database.
    </p>
    <${ResetEverything} onChanged=${onChanged} />
    <hr style="border-color:var(--color-border);margin:16px 0" />
    <${RegenerateKey} />
  </div>`;
}

// v2: rotating the app-wide access key. Everyone else's stored key stops
// working the instant this succeeds — that is the point of a rotation, not
// a side effect to work around — so this tab re-stores the new key for
// itself immediately after, rather than also logging out the person who
// deliberately triggered it.
function RegenerateKey() {
  const [open, setOpen] = useState(false);
  const [typed, setTyped] = useState('');
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState(null);
  const phrase = 'REGENERATE KEY';

  const go = async () => {
    setBusy(true);
    try {
      const { key } = await store.rotateAuthKey();
      setStoredKey(key);
      setResult({ ok: true, key });
      setTyped(''); setOpen(false);
    } catch (e) {
      setResult({ ok: false, message: e.message });
    } finally {
      setBusy(false);
    }
  };

  return html`<div class="danger-row">
    <div>
      <strong>Regenerate the access key</strong>
      <div class="subtle">Every browser currently signed in — except this one —
        stops working immediately. Share the new key with anyone who needs it;
        it is shown once, here, and never again.</div>

      ${!open
        ? html`<div style="margin-top:10px">
            <button class="btn btn-danger btn-sm" onClick=${() => setOpen(true)}>
              Regenerate key…
            </button></div>`
        : html`<div style="margin-top:10px">
            <div style="display:flex;gap:8px;flex-wrap:wrap">
              <input class="input" style="min-width:240px"
                placeholder=${`Type ${phrase} to confirm`} value=${typed}
                onInput=${(e) => setTyped(e.target.value)} />
              <button class="btn btn-danger" disabled=${busy || typed !== phrase}
                onClick=${go}>${busy ? 'Regenerating…' : 'Regenerate key'}</button>
              <button class="btn" onClick=${() => { setOpen(false); setTyped(''); }}>
                Cancel</button>
            </div>
          </div>`}

      ${result && result.ok && html`<div class="banner info" style="margin-top:10px">
        <span>✓</span><div>New key: <code>${result.key}</code> — this browser stays
          signed in; every other one now needs this new key.</div>
      </div>`}
      ${result && !result.ok && html`<div class="banner error" style="margin-top:10px">
        <span>✕</span><div>${result.message}</div></div>`}
    </div>
  </div>`;
}

function ResetEverything({ onChanged }) {
  const [open, setOpen] = useState(false);
  const [typed, setTyped] = useState('');
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState(null);

  const go = async () => {
    setBusy(true);
    try {
      const out = await store.resetAll();
      setResult({ ok: true, out });
      setTyped(''); setOpen(false);
      onChanged && onChanged();
    } catch (e) {
      setResult({ ok: false, message: e.message });
    } finally {
      setBusy(false);
    }
  };

  return html`<div class="danger-row">
    <div>
      <strong>Start completely fresh</strong>
      <div class="subtle">Empties the whole database — every project, every scan,
        every archived file. The app stays installed and configured.</div>

      ${!open
        ? html`<div style="margin-top:10px">
            <button class="btn btn-danger btn-sm" onClick=${() => setOpen(true)}>
              Delete everything…
            </button></div>`
        : html`<div style="margin-top:10px">
            <div style="display:flex;gap:8px;flex-wrap:wrap">
              <input class="input" style="min-width:240px"
                placeholder=${`Type ${RESET_PHRASE} to confirm`} value=${typed}
                onInput=${(e) => setTyped(e.target.value)} />
              <button class="btn btn-danger" disabled=${busy || typed !== RESET_PHRASE}
                onClick=${go}>${busy ? 'Deleting…' : 'Delete everything'}</button>
              <button class="btn" onClick=${() => { setOpen(false); setTyped(''); }}>
                Cancel</button>
            </div>
            <div class="subtle" style="margin-top:6px">
              The phrase is case-sensitive, and the server checks it too.
            </div>
          </div>`}

      ${result && result.ok && html`<div class="banner info" style="margin-top:10px">
        <span>✓</span><div>Store emptied:${' '}
          ${num(result.out.removed.projects)} projects,${' '}
          ${num(result.out.removed.runs)} scans, and${' '}
          ${num(result.out.removed.raw_archives)} archived files removed.</div>
      </div>`}
      ${result && !result.ok && html`<div class="banner error" style="margin-top:10px">
        <span>✕</span><div>${result.message}</div></div>`}
    </div>
  </div>`;
}

// ── Per-run delete ──────────────────────────────────────────────────────────

export function DeleteRunButton({ run, onDeleted }) {
  // Hooks first, then the early return. `SNAP` never changes at runtime so the
  // other order happens to work, but a conditional return above a hook is the
  // kind of thing that breaks silently the moment the condition becomes dynamic.
  const [armed, setArmed] = useState(false);
  const [busy, setBusy] = useState(false);

  if (SNAP) return null;
  if (!armed) {
    return html`<button class="btn btn-sm btn-danger" title="Delete this scan"
      onClick=${() => setArmed(true)}>Delete</button>`;
  }
  return html`<span style="display:inline-flex;gap:6px;align-items:center">
    <span class="subtle nowrap">Sure?</span>
    <button class="btn btn-sm btn-danger" disabled=${busy} onClick=${async () => {
      setBusy(true);
      try {
        await store.deleteRun(run.id, run.run_key);
        onDeleted && onDeleted();
      } catch (e) {
        alert(e.message);
      } finally {
        setBusy(false); setArmed(false);
      }
    }}>${busy ? '…' : 'Yes, delete'}</button>
    <button class="btn btn-sm" onClick=${() => setArmed(false)}>No</button>
  </span>`;
}

export { when };
