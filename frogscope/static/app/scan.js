// Running a scan from the browser.
//
// This is the only screen that causes outbound traffic, so it is built to make
// that obvious rather than convenient:
//
// * an authorisation checkbox that must be ticked, every time
// * choices rather than a flag box — a free-text httpx argument field would be
//   command injection with extra steps, so the server only accepts named options
// * a pause once the host count is known, because a number typed before you know
//   the size of an estate is not informed consent
// * a cancel button that actually stops the workers
//
// If the tools are not installed the panel says so and points at Docker, rather
// than offering a button that fails.

import { h } from 'preact';
import { useEffect, useRef, useState } from 'preact/hooks';
import htm from 'htm';
import { SNAP, store } from './store.js';
import { CardTitle, Help } from './help.js';
import { num } from './lib.js';
import { takePendingScanTargets } from './discovered.js';

const html = htm.bind(h);

const ACTIVE = ['running', 'ingesting', 'awaiting_approval', 'resolving_targets',
  'port_scanning', 'correlating'];

// Rough, client-side only — real validation is `classify_target()` on the
// server (frogscope/scan/options.py), which is what actually decides. This
// just previews the split before the user submits.
function classifyPreview(text) {
  const entries = text.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean);
  let domains = 0, ips = 0, cidrs = 0, unknown = 0;
  for (const entry of entries) {
    const bare = entry.replace(/^[a-z]+:\/\//i, '').split('/');
    const host = bare[0];
    const hasSlashSuffix = entry.includes('/') && /^[0-9a-f:.]+\/\d{1,3}$/i.test(entry);
    if (hasSlashSuffix) cidrs++;
    else if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || (host.includes(':') && /^[0-9a-f:]+$/i.test(host))) ips++;
    else if (/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i.test(host)) domains++;
    else unknown++;
  }
  return { total: entries.length, domains, ips, cidrs, unknown };
}

export function ScanPanel({ project, onIngested, embedded }) {
  const [tools, setTools] = useState(null);
  const [targets, setTargets] = useState('');
  const [profile, setProfile] = useState('');
  const [flags, setFlags] = useState({});
  const [label, setLabel] = useState('');
  const [subfinder, setSubfinder] = useState(true);
  const [authorised, setAuthorised] = useState(false);
  const [rateLimit, setRateLimit] = useState(150);
  const [advanced, setAdvanced] = useState(false);
  const [job, setJob] = useState(null);
  const [error, setError] = useState('');
  const poll = useRef(null);

  useEffect(() => {
    if (SNAP) return;
    store.scanTools().then((info) => {
      setTools(info);
      if (info.options) {
        setProfile(info.options.default_profile);
        const initial = {};
        for (const [key, spec] of Object.entries(info.options.flags)) {
          initial[key] = spec.default;
        }
        setFlags(initial);
      }
    }).catch((e) => setError(e.message));

    // A scan started before this page was loaded is still running on the server.
    // Finding it again matters: otherwise a reload looks like the scan vanished
    // and the natural response is to start a second one.
    store.scanList().then((list) => {
      const live = list.find((s) => ACTIVE.includes(s.state));
      if (live) setJob(live);
    }).catch(() => {});

    // Names queued from the "Newly discovered" tab (v2) — added with
    // consent, one click at a time there, prefilled here rather than
    // auto-probed the moment they were found.
    const pending = takePendingScanTargets();
    if (pending.length) {
      setTargets((prev) => (prev ? `${prev}\n${pending.join('\n')}` : pending.join('\n')));
    }
  }, []);

  // Poll while anything is in flight, and stop as soon as it is not.
  useEffect(() => {
    if (!job || !ACTIVE.includes(job.state)) {
      if (poll.current) { clearInterval(poll.current); poll.current = null; }
      return undefined;
    }
    poll.current = setInterval(async () => {
      try {
        const next = await store.scanStatus(job.job_id);
        setJob(next);
        if (next.state === 'done') onIngested && onIngested(next);
      } catch (e) {
        setError(e.message);
        clearInterval(poll.current);
        poll.current = null;
      }
    }, 2000);
    return () => { if (poll.current) clearInterval(poll.current); };
  }, [job && job.job_id, job && job.state]);

  const start = async () => {
    setError('');
    try {
      const started = await store.scanStart({
        project,
        label: label || undefined,
        targets,
        profile,
        flags,
        subfinder,
        authorised,
        rate_limit: Number(rateLimit),
      });
      setJob({ ...started, state: 'running', progress: {} });
    } catch (e) {
      setError(e.message);
    }
  };

  if (SNAP) return null;

  if (tools && !tools.ready) {
    return html`<div class="card" style="margin-bottom:16px">
      <${CardTitle} topic="scan.run">Run a scan<//>
      <div class="banner" style="margin-bottom:0">
        <span>▲</span><div>
          <strong>The scanners are not installed here.</strong>
          ${Object.values(tools.tools).filter((t) => !t.available).map((t) => html`
            <div style="margin-top:6px">
              <code>${t.name}</code> — ${t.purpose}<br/>
              <span class="subtle">${t.install_hint}</span>
            </div>`)}
          <div style="margin-top:8px">The Docker image bundles both:${' '}
            <code>docker compose up</code>. Or upload a scan file below — the
            analysis is identical either way.</div>
        </div></div>
    </div>`;
  }

  const options = tools && tools.options;
  const busy = job && ACTIVE.includes(job.state);
  // Client-side preview only — classify_target() on the server is what
  // actually decides. Domain count drives the enumeration-time estimate,
  // same as before; ip/cidr counts are new (v2).
  const breakdown = classifyPreview(targets);
  const domainCount = breakdown.domains;
  const hasNonDomainTargets = breakdown.ips > 0 || breakdown.cidrs > 0;
  // A range's true size is not obvious from its prefix length — shown above
  // the authorisation checkbox so ticking it is informed consent, not a
  // guess. IPv4 only: a v6 range's address count is astronomical and not a
  // useful number to display even when calculable.
  const cidrAddressTotal = (() => {
    if (!breakdown.cidrs) return null;
    let total = 0;
    let matched = false;
    for (const entry of targets.split(/[\s,]+/).map((s) => s.trim())) {
      const m = entry.match(/^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/);
      if (m) { total += 2 ** (32 - Number(m[2])); matched = true; }
    }
    return matched ? total : null;
  })();

  // A few hundred domains is a long enumeration even in parallel. Saying so up
  // front is the difference between "still working" and "it has hung".
  const limits = (options && options.limits) || {};
  const estimate = (() => {
    if (!domainCount || !limits.seconds_per_domain) return '';
    const workers = Math.max(1, Math.min(limits.enumeration_workers || 1,
                                         domainCount));
    const seconds = Math.ceil(domainCount / workers) * limits.seconds_per_domain;
    if (seconds < 120) return '';
    const minutes = Math.round(seconds / 60);
    return minutes < 90
      ? `Finding subdomains will take roughly ${minutes} minutes.`
      : `Finding subdomains will take roughly ${Math.round(minutes / 60)} hours — `
        + 'it runs in the background and you can cancel at any point.';
  })();
  // tlsx (one TLS handshake per host) and dnsx/mapcidr run on every scan now
  // — worth a word, not a precise number, since the actual duration depends
  // entirely on how many hosts end up probed.
  const correlateEstimate = domainCount || hasNonDomainTargets
    ? 'DNS, network, and certificate analysis run as part of every scan, '
      + 'adding a certificate handshake per host on top of this.'
    : '';

  const Wrapper = embedded ? 'div' : 'div';
  return html`<${Wrapper} class=${embedded ? '' : 'card'}
    style=${embedded ? '' : 'margin-bottom:16px'}>
    ${!embedded && html`<${CardTitle} topic="scan.run">Run a scan<//>`}

    ${!busy && html`<div>
      <p class="subtle" style="margin:0 0 10px">
        ${embedded
          ? html`Finds subdomains of the domains you enter, probes what answers,
              and files the result in this project.`
          : html`Finds subdomains, probes what answers, and files the result in${' '}
              <strong>${project || 'this project'}</strong> — the same as uploading
              a file, without the round trip.`}
      </p>

      <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:flex-start">
        <div style="flex:1;min-width:280px">
          <label class="subtle" style="display:block;margin-bottom:4px">
            Domains, IP addresses, and/or address ranges — one per line, or comma separated
          </label>
          <textarea class="input" rows="4" style="width:100%"
            placeholder=${'acme.com\nacme.co.uk\n203.0.113.0/24'}
            value=${targets}
            onInput=${(e) => setTargets(e.target.value)}></textarea>
          <div class="subtle" style="margin-top:4px">
            ${breakdown.total
              ? html`
                  ${breakdown.domains ? `${breakdown.domains} domain${breakdown.domains === 1 ? '' : 's'}` : ''}
                  ${breakdown.domains && (breakdown.ips || breakdown.cidrs) ? ' · ' : ''}
                  ${breakdown.ips ? `${breakdown.ips} address${breakdown.ips === 1 ? '' : 'es'}` : ''}
                  ${breakdown.ips && breakdown.cidrs ? ' · ' : ''}
                  ${breakdown.cidrs ? `${breakdown.cidrs} range${breakdown.cidrs === 1 ? '' : 's'}` : ''}
                  ${breakdown.unknown ? html` · <span style="color:var(--status-high)">${breakdown.unknown} not understood</span>` : ''}
                  ${domainCount ? html` — subdomains of ${domainCount === 1 ? 'it' : 'all of them'} are found, merged, and probed as one scan.${estimate ? html` ${estimate}` : ''}` : ''}
                  ${correlateEstimate ? html` ${correlateEstimate}` : ''}
                `
              : html`Add every domain the organisation owns — live brands, country
                  domains, parked and defensive registrations — plus any IP addresses
                  or ranges you want probed directly. A domain you forget is a domain
                  nobody is watching.`}
          </div>
        </div>
        <div style="min-width:200px">
          <label class="subtle" style="display:block;margin-bottom:4px">
            Label (optional)
          </label>
          <input class="input" style="width:100%"
            placeholder="e.g. 2026-07 monthly"
            value=${label} onInput=${(e) => setLabel(e.target.value)} />
        </div>
      </div>

      ${options && html`<div style="margin-top:10px">
        <label class="subtle" style="display:block;margin-bottom:4px">
          How many ports to check<//>
        <select class="input" value=${profile}
          onChange=${(e) => setProfile(e.target.value)}>
          ${Object.entries(options.profiles).map(([key, spec]) => html`
            <option value=${key}>
              ${spec.label}${' '}(${spec.port_count} ports)
            </option>`)}
        </select>
        <div class="subtle" style="margin-top:4px">
          ${(options.profiles[profile] || {}).note || ''}
        </div>
      </div>`}

      ${!hasNonDomainTargets || domainCount ? html`<div style="margin-top:10px">
        <label class="facet-row" style="width:auto">
          <input type="checkbox" checked=${subfinder}
            onChange=${(e) => setSubfinder(e.target.checked)} />
          <span class="label">Find subdomains first (passive sources only)</span>
        </label>
        <div class="subtle" style="margin-left:22px">
          ${subfinder
            ? 'Untick to probe only the domains you typed.'
            : 'Only the domains above will be probed.'}
        </div>
      </div>` : null}

      ${options && html`<div style="margin-top:12px">
        <button class="btn btn-sm" onClick=${() => setAdvanced(!advanced)}>
          ${advanced ? '▾' : '▸'} What to collect
        </button>
        ${advanced && html`<div style="margin-top:8px">
          <p class="subtle" style="margin:0 0 8px">
            Each of these turns on checks that are otherwise inert. More data means
            a slower scan.
          </p>
          ${(options.flag_order || Object.keys(options.flags)).map((key) => {
            const spec = options.flags[key];
            return html`
            <label class="facet-row" style="width:auto;align-items:flex-start">
              <input type="checkbox" checked=${Boolean(flags[key])}
                onChange=${(e) => setFlags({ ...flags, [key]: e.target.checked })} />
              <span>
                <span class="label">${spec.label}</span>
                <div class="subtle">${spec.note}</div>
              </span>
            </label>`;
          })}
          <div style="margin-top:10px;display:flex;gap:8px;align-items:center">
            <span class="subtle">Requests per second</span>
            <input class="input" type="number" style="width:90px"
              min=${options.limits.rate_limit[0]}
              max=${options.limits.rate_limit[1]}
              value=${rateLimit}
              onInput=${(e) => setRateLimit(e.target.value)} />
            <span class="subtle">Lower is politer, and less likely to be
              rate-limited or noticed.</span>
          </div>
        </div>`}
      </div>`}

      <div class="banner" style="margin-top:14px">
        <span>▲</span><div>
          ${breakdown.cidrs > 0 ? html`<div style="margin-bottom:8px">
            ${cidrAddressTotal
              ? html`<strong>${num(cidrAddressTotal)} addresses</strong> across
                  ${breakdown.cidrs} range${breakdown.cidrs === 1 ? '' : 's'} would be
                  probed — shown here because a range's size isn't obvious from its
                  prefix alone.`
              : html`${breakdown.cidrs} address range(s) entered — the exact
                  address count is confirmed once each range is expanded.`}
          </div>` : null}
          <label class="facet-row" style="width:auto;align-items:flex-start">
            <input type="checkbox" checked=${authorised}
              onChange=${(e) => setAuthorised(e.target.checked)} />
            <span><strong>I am authorised to scan these targets.</strong>
              <div>This sends real requests to real infrastructure. Scanning
                something you do not own or have written permission to test may be
                unlawful.</div></span>
          </label>
        </div>
      </div>

      <div style="margin-top:10px">
        <button class="btn btn-primary"
          disabled=${!authorised || !targets.trim() || !project}
          onClick=${start}>Start scan</button>
        ${!project && html`<span class="subtle" style="margin-left:8px">
          Choose a project first.</span>`}
      </div>
    </div>`}

    ${busy && html`<${ScanProgress} job=${job}
      onApprove=${async () => {
        try {
          const next = await store.scanApprove(job.job_id);
          setJob({ ...next, state: 'running', progress: {} });
        } catch (e) { setError(e.message); }
      }}
      onCancel=${async () => {
        try { await store.scanCancel(job.job_id); } catch (e) { setError(e.message); }
      }} />`}

    ${job && !ACTIVE.includes(job.state)
      ? html`<${ScanOutcome} job=${job} onDismiss=${() => setJob(null)} />`
      : null}

    ${error && html`<div class="banner error" style="margin-top:10px">
      <span>✕</span><div>${error}</div></div>`}
  <//>`;
}

const PHASES = {
  starting: 'Starting',
  enumerating: 'Finding subdomains',
  resolving_targets: 'Resolving targets',
  awaiting_approval: 'Waiting for you',
  port_scanning: 'Scanning for open ports',
  probing: 'Probing hosts',
  correlating: 'Correlating assets',
  ingesting: 'Analysing results',
};

function ScanProgress({ job, onApprove, onCancel }) {
  const p = job.progress || {};
  const phase = PHASES[p.phase] || PHASES[job.state] || job.state;

  if (job.state === 'awaiting_approval') {
    return html`<div class="banner" style="margin-bottom:0">
      <span>▲</span><div>
        <strong>Found ${num(job.hosts_found)} hosts.</strong> Nothing has been
        probed yet — enumeration only reads public sources.
        <div style="margin-top:6px">Probing means sending requests to every one of
          them. On an estate this size that is a lot of traffic, and it will show up
          in someone's logs.</div>
        ${(job.host_sample || []).length ? html`<div class="subtle"
          style="margin-top:6px;font-family:var(--font-mono);font-size:11px">
          ${job.host_sample.slice(0, 6).join(', ')}${' '}
          ${job.hosts_found > 6 ? `… and ${num(job.hosts_found - 6)} more` : ''}
        </div>` : null}
        <div style="margin-top:10px;display:flex;gap:8px">
          <button class="btn btn-primary" onClick=${onApprove}>
            Probe all ${num(job.hosts_found)} hosts
          </button>
          <button class="btn" onClick=${onCancel}>Stop here</button>
        </div>
      </div></div>`;
  }

  const elapsed = p.elapsed || 0;
  const mins = Math.floor(elapsed / 60);

  return html`<div>
    <div class="banner info" style="margin-bottom:10px">
      <span>⧗</span><div>
        <strong>${phase}.</strong>${' '}${p.message || ''}
        <div class="subtle" style="margin-top:4px">
          ${p.domains_total > 1
            ? `domain ${p.domains_done || 0} of ${p.domains_total} · ` : ''}
          ${p.hosts_found ? `${num(p.hosts_found)} hosts` : ''}
          ${p.endpoints_found ? ` · ${num(p.endpoints_found)} live endpoints` : ''}
          ${elapsed ? ` · ${mins ? `${mins}m ` : ''}${elapsed % 60}s elapsed` : ''}
        </div>
        ${p.hosts_total && p.phase === 'probing' ? html`<div class="bar"
          style="margin-top:8px;max-width:320px">
          <span style=${`width:${Math.min(100, (p.endpoints_found / p.hosts_total) * 100)}%;background:var(--color-primary)`}></span>
        </div>
        <div class="subtle" style="margin-top:2px">
          Probing ${num(p.hosts_total)} hosts. A host with nothing listening
          produces no row, so this bar is a floor rather than a percentage.
        </div>` : null}
      </div></div>
    <button class="btn btn-sm btn-danger" onClick=${onCancel}>Stop the scan</button>
    ${(p.log || []).length ? html`<details style="margin-top:10px">
      <summary class="subtle" style="cursor:pointer">Activity</summary>
      <pre class="kv" style="margin-top:6px;padding:8px;max-height:160px;overflow:auto;font-size:11px">${p.log.slice(-15).join('\n')}</pre>
    </details>` : null}
  </div>`;
}

function ScanOutcome({ job, onDismiss }) {
  if (job.state === 'done' && job.run) {
    const s = job.run.summary || {};
    return html`<div class="banner info" style="margin-bottom:0">
      <span>✓</span><div>
        <strong>Scan complete — filed as ${job.run.run_key}.</strong>${' '}
        ${num(job.run.endpoint_count)} endpoints across
        ${' '}${num(job.run.host_count)} hosts.
        ${s.real_endpoints !== undefined ? html`<div style="margin-top:4px">
          ${num(s.real_endpoints)} are real services — the rest are proxy aliases
          and scan artefacts, which are set aside rather than counted.
        </div>` : null}
        ${(job.run.warnings || []).map((w) => html`
          <div class="subtle">▲ ${w}</div>`)}
        <div style="margin-top:8px">
          <button class="btn btn-sm" onClick=${onDismiss}>Run another</button>
        </div>
      </div></div>`;
  }

  const cancelled = job.state === 'cancelled';
  return html`<div class=${`banner ${cancelled ? '' : 'error'}`}
    style="margin-bottom:0">
    <span>${cancelled ? '⊘' : '✕'}</span><div>
      <strong>${cancelled ? 'Scan stopped.' : 'Scan failed.'}</strong>${' '}
      ${job.error || ''}
      <div style="margin-top:8px">
        <button class="btn btn-sm" onClick=${onDismiss}>Try again</button>
      </div>
    </div></div>`;
}

export { Help };
