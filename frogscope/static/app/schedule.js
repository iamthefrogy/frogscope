// Scheduled scanning (v2) — for a server that stays up 24/7 and should be
// rescanned on its own, without anyone remembering to click "Start scan".
//
// Every schedule runs through the exact same execution path a manual scan
// does (frogscope/scan/executor.py) — see scan/scheduler.py — so a scheduled
// run and one triggered from this page's own "Start scan" tab are
// indistinguishable once ingested.

import { h } from 'preact';
import { useEffect, useState } from 'preact/hooks';
import htm from 'htm';
import { SNAP, store } from './store.js';
import { when } from './lib.js';
import { CardTitle } from './help.js';

const html = htm.bind(h);

const PRESETS = [
  ['hourly', 'Every hour'],
  ['daily', 'Every day'],
  ['weekly', 'Every week'],
];
const WEEKDAYS = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'];

export function SchedulePanel({ project }) {
  const [schedules, setSchedules] = useState(null);
  const [error, setError] = useState('');
  const [showForm, setShowForm] = useState(false);

  const refresh = () => {
    if (!project) return;
    store.schedules(project).then(setSchedules).catch((e) => setError(e.message));
  };
  useEffect(() => { refresh(); }, [project]);

  // Meaningless in the offline export: `fetch` is shimmed there, so this
  // would look live and silently do nothing — same reasoning as DangerZone.
  if (SNAP) return null;
  if (!project) return null;

  return html`<div class="card" style="margin-bottom:16px">
    <${CardTitle} topic="scan.schedule">Scheduled scans<//>
    <p class="subtle" style="margin:0 0 10px">
      Rescans this project's targets on its own — useful for a server that
      stays up between the times anyone remembers to check on it.
    </p>

    ${error ? html`<div class="banner error" style="margin-bottom:10px">${error}</div>` : null}
    ${!schedules ? html`<div class="loading">Loading…</div>` : null}

    ${schedules && schedules.length ? html`<div class="scroll-x">
      <table class="plain">
        <thead><tr>
          <th>Name</th><th>Targets</th><th>Cadence</th><th>Host cap</th>
          <th>Last run</th><th></th>
        </tr></thead>
        <tbody>${schedules.map((s) => html`
          <${ScheduleRow} schedule=${s} onChanged=${refresh} />`)}</tbody>
      </table>
    </div>` : null}
    ${schedules && !schedules.length && !showForm
      ? html`<p class="subtle">No schedules yet.</p>` : null}

    ${!showForm
      ? html`<button class="btn btn-sm" style="margin-top:10px"
              onClick=${() => setShowForm(true)}>Add a schedule…</button>`
      : html`<${ScheduleForm} project=${project}
              onCreated=${() => { setShowForm(false); refresh(); }}
              onCancel=${() => setShowForm(false)} />`}
  </div>`;
}

function ScheduleRow({ schedule: s, onChanged }) {
  const [busy, setBusy] = useState(false);

  const toggle = async () => {
    setBusy(true);
    try { await store.updateSchedule(s.id, { enabled: !s.enabled }); onChanged(); }
    finally { setBusy(false); }
  };
  const runNow = async () => {
    setBusy(true);
    try { await store.runScheduleNow(s.id); onChanged(); }
    finally { setBusy(false); }
  };
  const remove = async () => {
    if (!confirm(`Delete the "${s.name}" schedule?`)) return;
    setBusy(true);
    try { await store.deleteSchedule(s.id); onChanged(); }
    finally { setBusy(false); }
  };

  const cadence = s.preset === 'weekly'
    ? `Weekly, ${WEEKDAYS[s.day_of_week ?? 0]} ${s.time_of_day || ''}`
    : s.preset === 'hourly' ? 'Hourly'
    : `Daily, ${s.time_of_day || ''}`;

  return html`<tr>
    <td>
      <strong>${s.name}</strong>
      ${!s.enabled ? html`<span class="chip" data-state="neutral" style="margin-left:6px">paused</span>` : null}
    </td>
    <td class="subtle" style="max-width:220px" title=${(s.targets || []).join(', ')}>
      ${(s.targets || []).slice(0, 2).join(', ')}${(s.targets || []).length > 2 ? '…' : ''}
    </td>
    <td>${cadence}</td>
    <td class="num right">${s.max_hosts_cap}</td>
    <td class="subtle nowrap">
      ${s.last_run_at ? when(s.last_run_at) : 'never'}
      ${s.last_skip_reason ? html`<div><span class="chip" data-state="warn" title=${s.last_skip_reason}>skipped</span></div>` : null}
    </td>
    <td class="right" style="white-space:nowrap">
      <button class="btn btn-sm" disabled=${busy} onClick=${runNow}>Run now</button>
      <button class="btn btn-sm" disabled=${busy} onClick=${toggle}>${s.enabled ? 'Pause' : 'Resume'}</button>
      <button class="btn btn-sm btn-danger" disabled=${busy} onClick=${remove}>Delete</button>
    </td>
  </tr>`;
}

function ScheduleForm({ project, onCreated, onCancel }) {
  const [name, setName] = useState('');
  const [targets, setTargets] = useState('');
  const [profile, setProfile] = useState('common');
  const [preset, setPreset] = useState('daily');
  const [timeOfDay, setTimeOfDay] = useState('03:00');
  const [dayOfWeek, setDayOfWeek] = useState(0);
  const [maxHostsCap, setMaxHostsCap] = useState(500);
  const [authorised, setAuthorised] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  const submit = async (e) => {
    e.preventDefault();
    setError('');
    setBusy(true);
    try {
      await store.createSchedule(project, {
        name,
        targets: targets.split(/[\s,]+/).map((t) => t.trim()).filter(Boolean),
        profile,
        preset,
        time_of_day: timeOfDay,
        day_of_week: preset === 'weekly' ? Number(dayOfWeek) : null,
        max_hosts_cap: Number(maxHostsCap),
        authorised,
        subfinder: true,
      });
      onCreated();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  return html`<form class="toolbar" style="flex-direction:column;align-items:stretch;gap:10px;margin-top:10px" onSubmit=${submit}>
    <div style="display:flex;gap:8px;flex-wrap:wrap">
      <input class="input" style="flex:1;min-width:160px" placeholder="Name this schedule"
        value=${name} onInput=${(e) => setName(e.target.value)} required />
      <select class="input" value=${profile} onChange=${(e) => setProfile(e.target.value)}>
        <option value="web">Standard web (80, 443)</option>
        <option value="common">Common web and proxy ports</option>
        <option value="wide">Wide</option>
      </select>
    </div>

    <textarea class="input" rows="2" style="width:100%;box-sizing:border-box"
      placeholder="Domains, IP addresses, and/or CIDR ranges — one per line, or comma-separated"
      value=${targets} onInput=${(e) => setTargets(e.target.value)} required></textarea>

    <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">
      <select class="input" value=${preset} onChange=${(e) => setPreset(e.target.value)}>
        ${PRESETS.map(([v, label]) => html`<option value=${v}>${label}</option>`)}
      </select>
      ${preset !== 'hourly' ? html`<input class="input" type="time" style="width:110px"
        value=${timeOfDay} onInput=${(e) => setTimeOfDay(e.target.value)} />` : null}
      ${preset === 'weekly' ? html`<select class="input" value=${dayOfWeek}
        onChange=${(e) => setDayOfWeek(e.target.value)}>
        ${WEEKDAYS.map((d, i) => html`<option value=${i}>${d}</option>`)}
      </select>` : null}
      <label class="subtle" style="display:flex;align-items:center;gap:6px">
        Max hosts per run
        <input class="input" type="number" min="1" style="width:90px"
          value=${maxHostsCap} onInput=${(e) => setMaxHostsCap(e.target.value)} />
      </label>
    </div>
    <p class="subtle" style="margin:0">
      A run whose targets expand past this cap is skipped and logged rather than
      probed unattended — there is nobody here at 3am to approve a surprise.
    </p>

    <label class="facet-row">
      <input type="checkbox" checked=${authorised}
        onChange=${(e) => setAuthorised(e.target.checked)} />
      I am authorised to scan these targets, on every unattended run this
      schedule triggers.
    </label>

    ${error ? html`<div class="banner error">${error}</div>` : null}

    <div style="display:flex;gap:8px">
      <button class="btn btn-primary" type="submit" disabled=${busy || !authorised}>
        ${busy ? 'Saving…' : 'Save schedule'}</button>
      <button class="btn" type="button" onClick=${onCancel}>Cancel</button>
    </div>
  </form>`;
}
