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

// ── Collision-aware scheduling ───────────────────────────────────────────
//
// Two schedules "collide" when they'd both fire at the same time, piling
// unattended scan traffic onto the same minute instead of spreading it out.
// A daily schedule occupies its time on every day of the week; a weekly one
// occupies just its one day — so a candidate has to be checked against both.
// Hourly schedules are a separate domain (only the minute-of-hour repeats),
// so they're only checked against each other.
const pad2 = (n) => String(n).padStart(2, '0');

// Quiet hours first (01:00-05:30), so a fresh recommendation naturally lands
// off-peak; the rest of the day is the fallback once those run out.
const QUIET_TIMES = [];
for (let h = 1; h <= 5; h++) for (const m of [0, 30]) QUIET_TIMES.push(`${pad2(h)}:${pad2(m)}`);
const ALL_TIMES = [];
for (let h = 0; h < 24; h++) for (const m of [0, 30]) ALL_TIMES.push(`${pad2(h)}:${pad2(m)}`);
const TIME_CANDIDATES = [...QUIET_TIMES, ...ALL_TIMES.filter((t) => !QUIET_TIMES.includes(t))];

function occupiedAt(schedules, time) {
  let allDays = false;
  const days = new Set();
  for (const s of schedules) {
    if (!s.enabled || s.time_of_day !== time) continue;
    if (s.preset === 'daily') allDays = true;
    else if (s.preset === 'weekly') days.add(s.day_of_week ?? 0);
  }
  return { allDays, days };
}

/** First non-colliding daily time, or the first quiet-hours time if every
 * candidate is already taken (better to still suggest something than none). */
function suggestDailyTime(schedules) {
  for (const t of TIME_CANDIDATES) {
    const occ = occupiedAt(schedules, t);
    if (!occ.allDays && occ.days.size === 0) return { time: t, clashFree: true };
  }
  return { time: QUIET_TIMES[0], clashFree: false };
}

/** First non-colliding (day, time) pair for a weekly schedule, trying the
 * caller's preferred day first before spreading to the rest of the week. */
function suggestWeeklySlot(schedules, preferredDay) {
  const order = [preferredDay, ...WEEKDAYS.map((_, i) => i).filter((i) => i !== preferredDay)];
  for (const day of order) {
    for (const t of TIME_CANDIDATES) {
      const occ = occupiedAt(schedules, t);
      if (!occ.allDays && !occ.days.has(day)) return { day, time: t, clashFree: true };
    }
  }
  return { day: preferredDay, time: QUIET_TIMES[0], clashFree: false };
}

/** First unused top-of-hour minute for an hourly schedule. */
function suggestHourlyMinute(schedules) {
  const used = new Set(schedules
    .filter((s) => s.enabled && s.preset === 'hourly')
    .map((s) => parseInt((s.time_of_day || '00:00').split(':')[1], 10)));
  const candidates = [0, 15, 30, 45, 5, 10, 20, 25, 35, 40, 50, 55];
  for (const m of candidates) if (!used.has(m)) return { time: `00:${pad2(m)}`, clashFree: true };
  return { time: '00:00', clashFree: false };
}

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
          <th>Name</th><th>Targets</th><th>Cadence</th>
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

function cadenceText(s) {
  return s.preset === 'weekly'
    ? `Weekly, ${WEEKDAYS[s.day_of_week ?? 0]} ${s.time_of_day || ''}`
    : s.preset === 'hourly' ? 'Hourly'
    : `Daily, ${s.time_of_day || ''}`;
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

  const cadence = cadenceText(s);

  return html`<tr>
    <td>
      <strong>${s.name}</strong>
      ${!s.enabled ? html`<span class="chip" data-state="neutral" style="margin-left:6px">paused</span>` : null}
    </td>
    <td class="subtle" style="max-width:220px" title=${(s.targets || []).join(', ')}>
      ${(s.targets || []).slice(0, 2).join(', ')}${(s.targets || []).length > 2 ? '…' : ''}
    </td>
    <td>${cadence}</td>
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

// `initial*` props let a caller that already has targets/profile/authorised
// typed in elsewhere (`ScanPanel`'s inline "Schedule scan") seed this form
// with them instead of asking for the same three things twice. Purely
// initial state — editing them here doesn't reach back to the caller, same
// one-way relationship `SchedulePanel`'s own standalone use of this form
// already has with nothing.
export function ScheduleForm({ project, onCreated, onCancel,
                              initialTargets, initialProfile, initialAuthorised }) {
  const [name, setName] = useState('');
  const [targets, setTargets] = useState(initialTargets || '');
  const [profile, setProfile] = useState(initialProfile || 'common');
  const [preset, setPreset] = useState('daily');
  const [timeOfDay, setTimeOfDay] = useState('03:00');
  const [dayOfWeek, setDayOfWeek] = useState(0);
  const [authorised, setAuthorised] = useState(Boolean(initialAuthorised));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  // Every schedule across every project, fetched once — used to recommend a
  // day/time that doesn't collide with anything already scheduled. Manually
  // editing time or day marks that field "touched" so the recommendation
  // stops overwriting a deliberate choice.
  const [allSchedules, setAllSchedules] = useState(null);
  const [suggestion, setSuggestion] = useState(null);
  const [timeTouched, setTimeTouched] = useState(false);
  const [dayTouched, setDayTouched] = useState(false);

  useEffect(() => {
    store.allSchedules().then(setAllSchedules).catch(() => setAllSchedules([]));
  }, []);

  useEffect(() => {
    if (!allSchedules) return;
    let next;
    if (preset === 'hourly') next = suggestHourlyMinute(allSchedules);
    else if (preset === 'weekly') next = suggestWeeklySlot(allSchedules, Number(dayOfWeek));
    else next = suggestDailyTime(allSchedules);
    setSuggestion(next);
    if (!timeTouched) setTimeOfDay(next.time);
    if (preset === 'weekly' && !dayTouched && next.day !== undefined) setDayOfWeek(next.day);
    // Re-suggest whenever the cadence changes, or once schedules arrive —
    // deliberately not reacting to `dayOfWeek`/`timeOfDay` themselves, or a
    // user's own edit would immediately get recomputed out from under them.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [preset, allSchedules]);

  // A user picking a different day (weekly only) should re-suggest the time
  // for *that* day, without touching the day they just chose themselves.
  useEffect(() => {
    if (!allSchedules || preset !== 'weekly' || !dayTouched) return;
    const next = suggestWeeklySlot(allSchedules, Number(dayOfWeek));
    setSuggestion(next);
    if (!timeTouched) setTimeOfDay(next.time);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dayOfWeek]);

  const applySuggestion = () => {
    if (!suggestion) return;
    setTimeOfDay(suggestion.time);
    setTimeTouched(false);
    if (preset === 'weekly' && suggestion.day !== undefined) {
      setDayOfWeek(suggestion.day);
      setDayTouched(false);
    }
  };

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
        value=${timeOfDay}
        onInput=${(e) => { setTimeOfDay(e.target.value); setTimeTouched(true); }} />` : null}
      ${preset === 'weekly' ? html`<select class="input" value=${dayOfWeek}
        onChange=${(e) => { setDayOfWeek(e.target.value); setDayTouched(true); }}>
        ${WEEKDAYS.map((d, i) => html`<option value=${i}>${d}</option>`)}
      </select>` : null}
    </div>

    ${suggestion ? html`<p class="subtle" style="margin:0">
      ${suggestion.clashFree
        ? html`Recommended slot, clear of every other schedule: <strong>${
            preset === 'weekly' ? `${WEEKDAYS[suggestion.day]} ` : ''}${suggestion.time}</strong>.`
        : html`Every quiet slot is already taken — closest pick: <strong>${
            preset === 'weekly' ? `${WEEKDAYS[suggestion.day]} ` : ''}${suggestion.time}</strong>,
            still overlaps something.`}
      ${(timeTouched || dayTouched)
        ? html` <button class="btn btn-sm" type="button" onClick=${applySuggestion}>Use this</button>`
        : null}
    </p>` : null}

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

// One table, every project's schedules together — the question this answers
// is "what's running when, across the whole estate", which per-project
// `SchedulePanel` can't show since it only ever sees one project at a time.
export function ScheduleSummaryView() {
  const [schedules, setSchedules] = useState(null);
  const [error, setError] = useState('');

  const refresh = () => {
    store.allSchedules().then(setSchedules).catch((e) => setError(e.message));
  };
  useEffect(() => { refresh(); }, []);

  if (SNAP) return html`<div class="view-scroll"><div class="empty">
    <p class="muted">Not available in the offline export.</p>
  </div></div>`;

  return html`<div class="view-scroll"><div class="card">
    <${CardTitle} topic="section.schedules">All schedules<//>
    <p class="subtle" style="margin:0 0 10px">
      Every scheduled scan, across every project, in one place — so two
      schedules never end up quietly clashing on the same time slot.
    </p>

    ${error ? html`<div class="banner error" style="margin-bottom:10px">${error}</div>` : null}
    ${!schedules ? html`<div class="loading">Loading…</div>` : null}

    ${schedules && schedules.length ? html`<div class="scroll-x">
      <table class="plain">
        <thead><tr>
          <th>Project</th><th>Schedule</th><th>Cadence</th><th>Last run</th>
        </tr></thead>
        <tbody>${schedules.map((s) => html`<tr>
          <td>${s.project_name}</td>
          <td>
            <strong>${s.name}</strong>
            ${!s.enabled ? html`<span class="chip" data-state="neutral" style="margin-left:6px">paused</span>` : null}
          </td>
          <td>${cadenceText(s)}</td>
          <td class="subtle nowrap">
            ${s.last_run_at ? when(s.last_run_at) : 'never'}
            ${s.last_skip_reason ? html`<div><span class="chip" data-state="warn" title=${s.last_skip_reason}>skipped</span></div>` : null}
          </td>
        </tr>`)}</tbody>
      </table>
    </div>` : null}
    ${schedules && !schedules.length
      ? html`<p class="subtle">No schedules yet — add one from a project's "Scans & projects" tab.</p>` : null}
  </div></div>`;
}
