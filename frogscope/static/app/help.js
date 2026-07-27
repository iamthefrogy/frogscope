// Help text, and the question-mark control that reveals it.
//
// All copy lives in one file so it can be edited without hunting through views,
// and so it can be reviewed as writing rather than as code.
//
// Written for somebody who has never seen the tool and is not a security
// engineer. Each entry answers three things in order:
//
//   what   this section is
//   how    it is worked out (where the number comes from)
//   why    it is worth your attention
//
// If an entry cannot answer "why should I care", the section probably should not
// exist.

import { h } from 'preact';
import { useEffect, useRef, useState } from 'preact/hooks';
import htm from 'htm';

const html = htm.bind(h);

export const HELP = {
  // ── Sections ──────────────────────────────────────────────────────────────
  'section.summary': {
    title: 'Summary',
    body: [
      'The one page to read if you read nothing else. It answers: how big is our internet-facing estate, how much of it needs work, and is that getting better or worse.',
      'Everything here counts HOSTS, not web addresses. One server can answer on a dozen ports and still be one thing to fix.',
      'Print-friendly, so it can go straight into a board pack.',
    ],
  },
  'section.fix': {
    title: 'What to fix',
    body: [
      'Every issue found, grouped by the rule that found it and ordered by how much it matters.',
      'Each one carries plain-English reasoning, the exact evidence it was based on, and what to do about it. Nothing is asserted without showing why.',
      'Start at the top. The order already accounts for how exposed the asset is and how valuable it looks.',
    ],
  },
  'section.changed': {
    title: 'What changed',
    body: [
      'The difference between two scans: what appeared, what disappeared, and what changed in place.',
      'Needs at least two scans. With one, there is nothing to compare and the tab says so rather than showing an empty chart.',
      'Assets that flicker in and out of every scan are separated out, so the headline numbers stay stable and you are not chasing noise.',
    ],
  },
  'section.assets': {
    title: 'Assets',
    body: [
      'The full inventory, filterable on every column. This is where you answer specific questions — "which production hosts have no firewall in front of them?"',
      'Also holds the breakdowns: software in use, hosting and IP concentration, login pages, and possible dangling DNS records.',
      'Press / anywhere in the app to jump to the search box.',
    ],
  },
  'section.data': {
    title: 'Data & setup',
    body: [
      'Upload scans, manage projects, delete data, and see exactly what the scan did and did not collect.',
      'The coverage view is the honest part: it lists what could NOT be checked, so a clean result is never mistaken for a clean estate.',
    ],
  },

  // ── Executive page ────────────────────────────────────────────────────────
  'exec.hero': {
    title: 'The headline number',
    body: [
      'The share of your hosts carrying at least one serious issue.',
      'Worked out per host, then a host counts once no matter how many ports it exposes. Counting web addresses instead would make a heavily-proxied estate look far healthier than it is.',
      'Read the direction arrow, not the absolute value. A single scan has no direction; from the second scan onward it tells you whether you are winning.',
    ],
  },
  'exec.posture': {
    title: 'Posture index',
    body: [
      'A 0–100 score where higher is better. It is a weighted roll-up of every finding, so one number can be tracked over time.',
      'Two versions are shown deliberately. By host is the one to plan against — a host is the unit of remediation. By endpoint is shown only for contrast, and it is almost always more flattering.',
      'When the two differ a lot, a proxy is multiplying near-identical endpoints. The gap is the point, not a bug.',
    ],
  },
  'exec.protection': {
    title: 'Protection coverage',
    body: [
      'How much of what is serving content has something in front of it — a firewall, a CDN, or a login.',
      '"Unprotected" means no filtering, no authentication, and no encryption. The internet reaches the server directly.',
      'A proxy in front is not the same as a firewall inspecting traffic, so those are counted separately rather than lumped together as "protected".',
    ],
  },
  'exec.narrative': {
    title: 'Written summary',
    body: [
      'Generated from the findings, not written by hand, so it cannot drift out of step with the data.',
      'Each theme names the number of hosts and the specific thing to do. Where a mitigation applies — a firewall in front of an old server — it says so, because that changes the urgency without removing the problem.',
    ],
  },

  // ── Findings ──────────────────────────────────────────────────────────────
  'findings.list': {
    title: 'How findings work',
    body: [
      'Each card is one RULE, listing every asset it fired on. Grouping this way turns "1,100 findings" into a couple of dozen decisions.',
      'Severity is how bad it is. Confidence is how sure we are: confirmed means the scan data proves it, probable means it is strongly implied, possible means it is worth checking. A version number is never proof of a vulnerability, so those stay possible.',
      'Findings resolve on their own when the signal disappears from a later scan.',
    ],
  },
  'findings.confidence': {
    title: 'Confidence levels',
    body: [
      'confirmed — the scan data settles it. No plain-text redirect means no plain-text redirect.',
      'probable — strongly implied but not proven, usually because it depends on something we cannot see from outside.',
      'possible — a fingerprint match. The software looks vulnerable; nothing was tested. Verify before acting.',
      'Keeping these apart is what stops the list becoming a wall of maybes that nobody trusts.',
    ],
  },

  // ── Grid ──────────────────────────────────────────────────────────────────
  'grid.filters': {
    title: 'Filtering',
    body: [
      'Every column filters. Options within one column are OR — pick prod and uat to see both. Different columns are AND.',
      'Counts beside each option update as you filter, so you can see what is left before clicking.',
      'The search box takes real syntax: env:prod no_waf:yes score:>40. Press / to focus it from anywhere.',
    ],
  },
  'grid.artifacts': {
    title: 'Why the row count is lower than the file',
    body: [
      'Two kinds of row are set aside because they are not separate services.',
      'Scan artefacts: the scanner tried plain HTTP on a port that only speaks encrypted HTTPS. The error it got back is the server behaving correctly — not a finding.',
      'Proxy alias ports: providers like Cloudflare accept a fixed set of extra ports that all serve the same site as 443. Counting them separately inflates the estate several times over.',
      'Both are still in the data and can be filtered back in. They are just kept out of the headline numbers.',
    ],
  },

  // ── Changes ───────────────────────────────────────────────────────────────
  'changes.diff': {
    title: 'How changes are worked out',
    body: [
      'Assets are matched between scans on hostname and port. Not on the web address, because a switch from http to https would otherwise look like one asset vanishing and another appearing.',
      'Hostname case is ignored. Without that, a scanner that reports Host.example.com one week and host.example.com the next reports every asset as new, forever.',
      'Fields that change on every scan for no real reason — timestamps, response times, single-use login tokens in redirect URLs — are excluded, or every login page would appear "changed" every week.',
    ],
  },
  'changes.flapping': {
    title: 'Flapping assets',
    body: [
      'Assets that appear and disappear repeatedly across scans. Usually load balancing or rate limiting, not real change.',
      'Held separately and kept out of the headline appeared/disappeared counts. A weekly report that cries wolf gets ignored, and then the real alert is missed too.',
    ],
  },
  'trends.chart': {
    title: 'Trends',
    body: [
      'Each metric over every scan, so you can see direction rather than a single snapshot.',
      'Metrics are stored per scan when it is ingested, so charts do not re-derive history and cannot quietly change as the rules change.',
      'If scoring rules were edited between scans, a moved line may be a re-scoring rather than a real-world change. The run list records which rule version each scan used.',
    ],
  },

  // ── Inventory views ───────────────────────────────────────────────────────
  'inventory.takeover': {
    title: 'Possible dangling records',
    body: [
      'A hostname you own that points at a third-party service which no longer has anything there. If that service lets anyone claim the name, someone else can publish content on your domain.',
      'These are always CANDIDATES. Nothing here is confirmed, because confirming it needs a live check and ingest sends no network traffic at all.',
      'To confirm: check whether the target still resolves and whether the provider allows the name to be re-registered. Each row shows the exact commands.',
    ],
  },
  'inventory.technology': {
    title: 'Software in use',
    body: [
      'What the scanner could identify, with end-of-life products called out and how long they have been unsupported.',
      '"Unsupported for 11 years" lands differently from a yes/no flag, which is why the age is shown.',
      'Detection comes from the scanner, so absence here means "not identified", not "not present".',
    ],
  },
  'inventory.infra': {
    title: 'Hosting and concentration',
    body: [
      'Which addresses and providers your estate depends on, and how much sits on each one.',
      'Concentration is a resilience question as much as a security one: many hostnames on one address means one failure or one compromise reaches all of them.',
      'Third-party dependencies are listed separately, because those are systems you rely on but do not control.',
    ],
  },
  'inventory.auth': {
    title: 'Login pages',
    body: [
      'Every sign-in page, admin console, and remote-access portal that is reachable.',
      'Whether the login is federated matters, and federation is GOOD — it means central identity, and central multi-factor. A local-only login is the one worth a closer look.',
      'Remote-access appliances are separated out because they are consistently among the most attacked things on the internet.',
    ],
  },
  'network.overview': {
    title: 'Network (v2)',
    body: [
      'Every address this scan resolved, with the block it falls in, its reverse DNS name, and who else shares it — from dnsx and mapcidr, the opt-in "Correlate assets" step.',
      'Foreign domains on an address are registrable domains you do not own, sharing the same server. Reverse DNS is the PTR record — the name an address answers to, independent of what DNS said it should be.',
      'Empty until a scan turns on "Correlate assets", the same as a certificate rule showing as skipped without -tls-grab — data that was never collected, not data that says everything is fine.',
    ],
  },
  'network.shared': {
    title: 'Shared addresses',
    body: [
      'Addresses serving the most registrable domains outside your portfolio — the ones with the largest blast radius if that address is compromised, abused, or blocklisted.',
      'Common and often fine on a CDN edge; worth a second look on infrastructure you believe you run alone.',
    ],
  },
  'network.cidrs': {
    title: 'Address blocks',
    body: [
      'CIDR ranges seen this scan — either because you scanned the range directly, or because mapcidr aggregated the individual addresses found into the smallest blocks that cover them.',
      '"Scan target" blocks were entered directly on the scan form; the rest were inferred from what was actually observed.',
    ],
  },
  'cert.inventory': {
    title: 'Certificates (v2)',
    body: [
      'Every TLS certificate tlsx found, sorted by days until expiry. This replaces httpx\'s partial view — httpx can report an expiry date with -tls-grab, but only tlsx checks trust, hostname match, and every other domain a certificate covers.',
      'Self-signed, mismatched, and untrusted are three different problems that look similar: self-signed means no authority vouches for it at all; mismatched means the certificate is for a different name; untrusted means the chain does not lead to something a browser trusts.',
      'A name marked ✦ was never seen in any prior scan of this project — the certificate is the only place it has shown up so far.',
    ],
  },
  'discovered.how': {
    title: 'Newly discovered',
    body: [
      'Domains this scan found evidence of but never directly enumerated — named in a certificate\'s SAN list, or answering reverse DNS on an address that was probed.',
      'Never probed automatically: doing so would mean scanning a name nobody entered, which defeats the point of the authorisation checkbox on the scan form. Add the ones worth investigating to the next scan instead — that keeps every probe consent-based.',
    ],
  },
  'inventory.panels': {
    title: 'Exposed consoles',
    body: [
      'Products identified from what the scan already returned — page title, technology, or software identifier. Never by requesting extra pages, because nothing here sends traffic.',
      'Grouped by how much authority the product carries. A build server can run code by design, so it ranks above a monitoring dashboard even when both are equally certain.',
      'Real limitation: a console at /admin on a host whose front page is a marketing site will NOT appear. The coverage view says how much of the catalogue could be checked at all.',
    ],
  },

  // ── Coverage and method ───────────────────────────────────────────────────
  'coverage.fill': {
    title: 'What the scan collected',
    body: [
      'Which columns actually have data. Empty ones are hidden automatically rather than shown as blank.',
      'This is where "we found nothing" gets qualified. Certificate expiry checks are written and correct, but they cannot run if the scan did not collect certificates — so they are reported as skipped, never as passing.',
      'The suggested command at the bottom lists the extra flags and exactly which checks each one switches on.',
    ],
  },
  'method.rules': {
    title: 'How scoring works',
    body: [
      'Every rule, its weight, the condition in readable form, and how many assets it fired on in this scan.',
      'Scores are capped per category, similar rules are de-duplicated so one problem is not counted five times, and mitigations like a firewall in front reduce but never erase a serious finding.',
      'All of it lives in editable configuration. If you disagree with a weight, change it and re-score — no code change.',
      'A rule firing on nearly everything is flagged here: that means it is mis-modelled, not that everything is broken.',
    ],
  },
  'scan.run': {
    title: 'Running a scan',
    body: [
      'Finds subdomains of the domains you enter, probes each one, and files the result in this project — the same as uploading a file, without the round trip.',
      'Enter as many primary domains as the organisation owns, one per line. A large company usually has several — a main brand, country domains, an acquisition or two. Subdomains of all of them are found, merged into one list, and probed together, so the project holds the whole estate rather than a fragment of it.',
      'This is the ONLY part of the tool that sends traffic. Everything else reads a file. Subdomain discovery is passive (public sources only); probing is not, so you are asked to confirm you are authorised, and asked again once the number of hosts is known.',
      'You pick from named options rather than typing scanner flags. That is deliberate: a free-text argument box would let anything typed here run as a command.',
      'Each collection option turns on checks that are otherwise inert — certificate expiry needs certificates. More data means a slower scan.',
    ],
  },

  'scan.schedule': {
    title: 'Scheduled scans',
    body: [
      'Reruns this project\'s targets on its own — hourly, daily, or weekly — for an estate that keeps changing whether or not anyone is watching. Every scheduled run goes through the exact same path as clicking "Start scan" yourself, so a scheduled run and a manual one are indistinguishable once ingested.',
      'The host cap is the unattended-approval policy: a manual scan pauses and asks once the host count is known, but there is nobody at 3am to click "approve". A run whose targets expand past the cap is skipped and logged instead of silently probing further than was agreed when the schedule was created.',
      'Authorisation is confirmed once, when the schedule is saved — it applies to every unattended run that schedule triggers afterward, not just the first one.',
    ],
  },

  'runs.upload': {
    title: 'Adding a scan',
    body: [
      'Drop in output from httpx (CSV, JSON, or JSONL). The same database backs the command line, so scans added either way appear in both.',
      'Two safety checks: a scan that looks unfinished, and one that is a very different size from the last. Both can be accepted with one click, but they are not accepted silently — a truncated scan has fewer findings and would read as an improvement that never happened.',
      'Re-uploading the same file is detected and skipped rather than counted twice.',
    ],
  },
  'runs.projects': {
    title: 'Projects',
    body: [
      'A project keeps one target’s scans together. Comparisons never cross projects, so a client engagement cannot contaminate your own estate’s history.',
      'Use one per organisation or engagement.',
    ],
  },
  'runs.delete': {
    title: 'Deleting data',
    body: [
      'Three levels. One scan — the Delete button on its row. One project and all its scans — the Delete button beside the project selector above. Or the whole database, here.',
      'None of it can be undone, and the archived source files go too — so you cannot re-derive those scans later even if the analysis improves.',
      'Each one shows exactly what will be removed and makes you type the name back. The server checks that too.',
    ],
  },
};

/**
 * A question mark that fades an explanation in beside it.
 *
 * Closes on outside click and on Escape. Both matter: a panel that can only be
 * closed by finding the same small button again is worse than no panel.
 */
export function Help({ topic, align = 'left' }) {
  const [open, setOpen] = useState(false);
  const holder = useRef(null);
  const entry = HELP[topic];

  useEffect(() => {
    if (!open) return undefined;
    const onDown = (e) => {
      if (holder.current && !holder.current.contains(e.target)) setOpen(false);
    };
    const onKey = (e) => { if (e.key === 'Escape') setOpen(false); };
    document.addEventListener('mousedown', onDown);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onDown);
      document.removeEventListener('keydown', onKey);
    };
  }, [open]);

  // A missing topic renders nothing rather than an empty bubble, so adding a
  // Help before writing its copy cannot ship a dead control.
  if (!entry) return null;

  return html`<span class="help-holder" ref=${holder}>
    <button class="help-dot" aria-expanded=${open ? 'true' : 'false'}
      aria-label=${`What is ${entry.title}?`}
      onClick=${(e) => { e.stopPropagation(); setOpen(!open); }}>?</button>
    <span class=${`help-panel ${open ? 'open' : ''} ${align}`} role="note">
      <strong>${entry.title}</strong>
      ${entry.body.map((para) => html`<p>${para}</p>`)}
    </span>
  </span>`;
}

/** A card heading with its help control attached. */
export function CardTitle({ children, topic }) {
  return html`<h3 class="card-title">
    <span>${children}</span>${topic ? html`<${Help} topic=${topic} />` : null}
  </h3>`;
}
