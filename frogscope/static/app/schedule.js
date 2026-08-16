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
import { when, scopeKeyFor, loadPersistedScope, savePersistedScope } from './lib.js';
import { CardTitle } from './help.js';

const html = htm.bind(h);

const PRESETS = [
  ['hourly', 'Every hour'],
  ['daily', 'Every day'],
  ['weekly', 'Every week'],
];
const WEEKDAYS = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'];

// The device's own zone — what "09:35" means to whoever is sitting here
// typing it, not the server's. `time_of_day` is interpreted against this
// (scan/scheduler.py's `next_run_at`), so getting it wrong is the difference
// between a schedule that fires when you meant it to and one that silently
// fires hours off, which is exactly why this is auto-detected rather than
// left for someone to notice UTC on a dropdown and get right by luck.
function detectTimezone() {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
  } catch { return 'UTC'; }
}

// A handful of common zones plus whatever the browser reports, deduplicated
// — good enough for a dropdown without needing `Intl.supportedValuesOf`
// (not available in every browser this SPA has to run in).
function timezoneOptions(detected) {
  const common = [
    'UTC', 'Asia/Kolkata', 'Asia/Dubai', 'Asia/Singapore', 'Asia/Tokyo',
    'Asia/Shanghai', 'Europe/London', 'Europe/Berlin', 'Europe/Moscow',
    'America/New_York', 'America/Chicago', 'America/Denver',
    'America/Los_Angeles', 'America/Sao_Paulo', 'Australia/Sydney',
  ];
  return [...new Set([detected, ...common])];
}

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

// `time_of_day` is only comparable between schedules that read it in the
// same zone — "09:35" in Kolkata and "09:35" in London are ~5.5 hours apart,
// not a collision, so cross-zone schedules are ignored here rather than
// compared as if the strings meant the same instant. Old rows from before
// the `timezone` column existed default to `'UTC'` (the migration's column
// default), so they compare correctly against an explicit UTC pick too.
function occupiedAt(schedules, time, timezone) {
  let allDays = false;
  const days = new Set();
  for (const s of schedules) {
    if (!s.enabled || s.time_of_day !== time) continue;
    if ((s.timezone || 'UTC') !== (timezone || 'UTC')) continue;
    if (s.preset === 'daily') allDays = true;
    else if (s.preset === 'weekly') days.add(s.day_of_week ?? 0);
  }
  return { allDays, days };
}

/** First non-colliding daily time, or the first quiet-hours time if every
 * candidate is already taken (better to still suggest something than none). */
function suggestDailyTime(schedules, timezone) {
  for (const t of TIME_CANDIDATES) {
    const occ = occupiedAt(schedules, t, timezone);
    if (!occ.allDays && occ.days.size === 0) return { time: t, clashFree: true };
  }
  return { time: QUIET_TIMES[0], clashFree: false };
}

/** First non-colliding (day, time) pair for a weekly schedule, trying the
 * caller's preferred day first before spreading to the rest of the week. */
function suggestWeeklySlot(schedules, preferredDay, timezone) {
  const order = [preferredDay, ...WEEKDAYS.map((_, i) => i).filter((i) => i !== preferredDay)];
  for (const day of order) {
    for (const t of TIME_CANDIDATES) {
      const occ = occupiedAt(schedules, t, timezone);
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

  // A schedule can fire on the scheduler's own clock with nobody watching —
  // light polling is the only way this tab ever finds out, since nothing
  // pushes it a "your unattended run just started" event. Cheap (one small
  // SELECT) and only while this panel is actually open.
  useEffect(() => {
    if (SNAP || !project) return undefined;
    const id = setInterval(refresh, 5000);
    return () => clearInterval(id);
  }, [project]);

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
          <th>Next run</th><th>Last run</th><th></th>
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
  // Hourly has no `time_of_day`/timezone (only a minute-of-hour, matched the
  // same instant in every zone) — see `next_run_at`'s docstring.
  if (s.preset === 'hourly') return 'Hourly';
  const base = s.preset === 'weekly'
    ? `Weekly, ${WEEKDAYS[s.day_of_week ?? 0]} ${s.time_of_day || ''}`
    : `Daily, ${s.time_of_day || ''}`;
  return s.timezone ? `${base} (${s.timezone})` : base;
}

// `next_run_at` is stored in UTC (scan/scheduler.py) — shown here in the
// schedule's own timezone, the one the user actually picked a time in, so
// "next run" reads as the same clock they set rather than a UTC instant
// they'd have to convert in their head to know if it's already overdue.
function formatNextRun(s) {
  if (!s.enabled) return 'paused';
  if (!s.next_run_at) return '—';
  const d = new Date(s.next_run_at);
  if (Number.isNaN(d.getTime())) return s.next_run_at;
  try {
    return new Intl.DateTimeFormat(undefined, {
      timeZone: s.timezone || 'UTC',
      year: 'numeric', month: 'short', day: '2-digit',
      hour: '2-digit', minute: '2-digit', hour12: false,
    }).format(d);
  } catch {
    return `${when(s.next_run_at)} UTC`;
  }
}

function ScheduleRow({ schedule: s, onChanged }) {
  const [busy, setBusy] = useState(false);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState('');
  // `running` is this browser's own click; `s.running` is the scheduler's
  // tick firing this schedule on its own clock, polled in from the server
  // (SchedulePanel's 5s refresh) — either one means "show it as in
  // progress", since neither alone covers both ways a run can start.
  const isRunning = running || Boolean(s.running);

  const toggle = async () => {
    setBusy(true); setError('');
    try { await store.updateSchedule(s.id, { enabled: !s.enabled }); onChanged(); }
    catch (e) { setError(e.message); }
    finally { setBusy(false); }
  };
  // `run-now` runs the scan inline on the server (routes.py) — this can take
  // minutes, so the button needs its own "Running…" state rather than just
  // `busy`, or a slow run looks identical to a click that did nothing. And
  // without the try/catch this used to be missing, a rejected request (slot
  // held by another scan, tools not installed, etc) failed completely
  // silently: `busy` still got reset in `finally`, so the button just
  // re-enabled with no sign anything had gone wrong.
  const runNow = async () => {
    setBusy(true); setRunning(true); setError('');
    try { await store.runScheduleNow(s.id); onChanged(); }
    catch (e) { setError(e.message); }
    finally { setBusy(false); setRunning(false); }
  };
  const remove = async () => {
    if (!confirm(`Delete the "${s.name}" schedule?`)) return;
    setBusy(true); setError('');
    try { await store.deleteSchedule(s.id); onChanged(); }
    catch (e) { setError(e.message); }
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
    <td class="subtle nowrap">${formatNextRun(s)}</td>
    <td class="subtle nowrap">
      ${s.last_run_at ? when(s.last_run_at) : 'never'}
      ${s.last_skip_reason ? html`<div><span class="chip" data-state="warn" title=${s.last_skip_reason}>skipped</span></div>` : null}
      ${error ? html`<div><span class="chip" data-state="bad" title=${error}>run failed</span></div>` : null}
    </td>
    <td class="right" style="white-space:nowrap">
      <button class=${isRunning ? 'btn btn-sm btn-warn' : 'btn btn-sm'}
        disabled=${busy || isRunning} onClick=${runNow}>
        ${isRunning ? 'In progress…' : 'Run now'}</button>
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
// When there's no caller to hand targets over directly (`SchedulePanel`'s
// own "Add a schedule…"), fall back to the same remembered scope "Run a
// scan" prefills itself from — the two boxes share one memory now, so the
// same domain/IP list never needs retyping or copy-pasting between them.
export function ScheduleForm({ project, onCreated, onCancel,
                              initialTargets, initialProfile, initialAuthorised }) {
  const [name, setName] = useState('');
  const [targets, setTargets] = useState(initialTargets || '');
  const [profile, setProfile] = useState(initialProfile || 'common');
  const [preset, setPreset] = useState('daily');
  const [timeOfDay, setTimeOfDay] = useState('03:00');
  const [dayOfWeek, setDayOfWeek] = useState(0);
  const [timezone, setTimezone] = useState(detectTimezone());
  const [authorised, setAuthorised] = useState(Boolean(initialAuthorised));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  // The remembered-scope key for this specific backend project (slug + its
  // `created_at`, so a project recreated after a database wipe doesn't
  // inherit a previous cycle's memory — see `scopeKeyFor` in lib.js). Only
  // used to prefill when the caller hasn't already handed targets over
  // directly; always resolved, though, so a successful save below can use it
  // even in the `initialTargets` case.
  const [scopeKey, setScopeKey] = useState(null);
  useEffect(() => {
    if (!project) return;
    let cancelled = false;
    scopeKeyFor(project).then((key) => {
      if (cancelled) return;
      setScopeKey(key);
      if (!initialTargets) setTargets((prev) => prev || loadPersistedScope(key));
    });
    return () => { cancelled = true; };
  }, [project]);

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
    else if (preset === 'weekly') next = suggestWeeklySlot(allSchedules, Number(dayOfWeek), timezone);
    else next = suggestDailyTime(allSchedules, timezone);
    setSuggestion(next);
    if (!timeTouched) setTimeOfDay(next.time);
    if (preset === 'weekly' && !dayTouched && next.day !== undefined) setDayOfWeek(next.day);
    // Re-suggest whenever the cadence, timezone, or schedule list changes —
    // deliberately not reacting to `dayOfWeek`/`timeOfDay` themselves, or a
    // user's own edit would immediately get recomputed out from under them.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [preset, allSchedules, timezone]);

  // A user picking a different day (weekly only) should re-suggest the time
  // for *that* day, without touching the day they just chose themselves.
  useEffect(() => {
    if (!allSchedules || preset !== 'weekly' || !dayTouched) return;
    const next = suggestWeeklySlot(allSchedules, Number(dayOfWeek), timezone);
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
        timezone,
        authorised,
        subfinder: true,
      });
      // Remembered only now — the schedule was actually, deliberately saved
      // with this scope, not merely typed and possibly abandoned.
      savePersistedScope(scopeKey || project, targets);
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
      ${preset !== 'hourly' ? html`<select class="input" value=${timezone}
        onChange=${(e) => setTimezone(e.target.value)}>
        ${timezoneOptions(timezone).map((z) => html`<option value=${z}>${z}</option>`)}
      </select>` : null}
    </div>

    ${preset !== 'hourly' ? html`<p class="subtle" style="margin:0">
      Detected from this device: <strong>${detectTimezone()}</strong> — change the zone above
      if this schedule is for a server or team somewhere else.
    </p>` : null}

    ${suggestion ? html`<p class="subtle" style="margin:0">
      ${suggestion.clashFree
        ? html`Recommended slot, clear of every other schedule in this zone: <strong>${
            preset === 'weekly' ? `${WEEKDAYS[suggestion.day]} ` : ''}${suggestion.time}</strong>.`
        : html`Every quiet slot in this zone is already taken — closest pick: <strong>${
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

  // Same reasoning as `SchedulePanel`'s poll: a schedule can start on its
  // own clock with nobody watching, and this is the only way this tab finds
  // out short of a manual reload.
  useEffect(() => {
    if (SNAP) return undefined;
    const id = setInterval(refresh, 5000);
    return () => clearInterval(id);
  }, []);

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
          <th>Project</th><th>Schedule</th><th>Cadence</th><th>Next run</th><th>Last run</th>
        </tr></thead>
        <tbody>${schedules.map((s) => html`<tr>
          <td>${s.project_name}</td>
          <td>
            <strong>${s.name}</strong>
            ${!s.enabled ? html`<span class="chip" data-state="neutral" style="margin-left:6px">paused</span>` : null}
          </td>
          <td>${cadenceText(s)}</td>
          <td class="subtle nowrap">${formatNextRun(s)}</td>
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
