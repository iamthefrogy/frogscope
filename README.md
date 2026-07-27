# 🐸 Frogscope

**An honest map of your internet-facing estate, and what changed since last time.**

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)

Point it at domains, IP addresses, or address ranges — mixed freely, in any
combination. It finds what is reachable, correlates domain↔IP↔certificate data,
tells you what needs fixing in plain English, and shows what moved since the last
scan.

Built on [subfinder](https://github.com/projectdiscovery/subfinder),
[naabu](https://github.com/projectdiscovery/naabu),
[httpx](https://github.com/projectdiscovery/httpx),
[dnsx](https://github.com/projectdiscovery/dnsx),
[mapcidr](https://github.com/projectdiscovery/mapcidr), and
[tlsx](https://github.com/projectdiscovery/tlsx) — all six bundled in the Docker
image. DNS/network analysis and TLS certificate reading run on every scan, not
behind a toggle. Ports, environment keywords, and every detection rule live in
editable `config/` files.

**Two Python dependencies.** No npm, no bundler, no build step, no telemetry.

> Just want to install and use it? **[USER_GUIDE.md](USER_GUIDE.md)** is the
> short version — what it is, who it's for, install, and UI navigation.
> Everything below is the deep-dive for developing and maintaining it.

---

## Contents

- [Quick start](#quick-start) · [Without Docker](#without-docker)
- [What makes it different](#what-makes-it-different)
- [What you get](#what-you-get)
- [Scanning responsibly](#scanning-responsibly)
- [What it cannot see](#what-it-cannot-see)
- [Day-to-day use](#day-to-day-use)
- [Maintenance](#maintenance) · [Checklist](#checklist)
- [Tuning](#tuning-it-for-your-estate)
- [Commands](#commands) · [Architecture](#architecture)
- [Contributing](#contributing)

---

## Quick start

```bash
git clone https://github.com/iamthefrogy/frogscope
cd frogscope
docker compose up --build
```

Open <http://127.0.0.1:8099>. Create a project, enter your targets, press **Start
scan**.

**Enter every primary domain, IP address, or address range the organisation
owns**, one per line, mixed freely — the form parses and classifies each line
itself and shows a live breakdown ("12 domains · 3 ranges · 2 not understood"). A
real portfolio is large — live brands, country domains, acquisitions, parked and
defensive registrations, plus whatever ranges you host on — so paste the whole
list. Subdomains of every domain are discovered concurrently and merged with any
IP/CIDR targets into one list, so one project holds the whole estate rather than a
fragment. *A domain — or a range — you forget is one nobody is watching.*

Enumeration is passive and runs several domains at a time; the form estimates how
long it will take before you start. naabu scans for open ports first, so httpx and
tlsx only spend time on host:port pairs something actually answers on — a scan
submitted is a scan that runs, with no interactive pause partway through asking
whether to continue. `MAX_HOSTS` (200,000) is still a hard, unconditional ceiling
against a genuinely runaway target list.

Want to look around first? The repo ships a synthetic scan:

```bash
docker compose run --rm frogscope ingest examples/demo-scan.csv \
    --project demo --project-name "Demo Estate" --label "example scan"
```

It is fabricated (`example.com` names, RFC 5737 addresses) and built to exercise
the interesting paths — an exposed build server, a Kubernetes dashboard, a
database console, a dangling DNS candidate sitting next to a broken origin that
must *not* be reported as one, end-of-life software, and a proxy that multiplies
one site across thirteen ports.

The container runs unprivileged with all capabilities dropped, and compose
publishes the port on `127.0.0.1` only. Your database lives in a named volume;
`./config` is mounted so your tuning survives a rebuild.

### Without Docker

The app needs nothing but Python:

```bash
python3 -m venv .venv && .venv/bin/pip install -e .
.venv/bin/frogscope init
.venv/bin/frogscope serve
```

Scanning needs subfinder and httpx on your `PATH` — without them the UI says so
and the upload path still works. naabu, dnsx, mapcidr, and tlsx are optional on
top of that: each degrades gracefully and is skipped (with a reason, visible in
**Data & setup → What was collected**) rather than blocking a scan, but a scan
without them loses the port-scan speedup and all DNS/network/TLS correlation. The
Docker image bundles all six; installing them yourself needs Go and libpcap
(naabu links against it):

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest
go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest
CGO_ENABLED=1 go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
```

### Already have httpx output?

Drop the CSV on the **Data & setup** tab, or:

```bash
frogscope ingest scan.csv --project acme --label "2026-07 monthly"
```

A scan run here and a file you uploaded produce **identical** runs. The analysis
never depends on how the data arrived, and you can mix both in one project.

---

## What makes it different

Most tools count rows. This one asks whether a row is a *service*.

From a real scan of ~330 hosts:

| | |
|---|---|
| Rows in the file | 2,212 |
| Unique endpoints after collapsing repeat probes | 2,078 |
| **Actually distinct services** | **943** |

The other 1,135 are noise that looks exactly like attack surface:

- **709 scan artefacts** — the scanner tried plain HTTP on a TLS-only port. The
  `400` it got back is the server behaving *correctly*. Left unclassified, this one
  meaningless category is a third of your dashboard.
- **786 proxy alias ports** — Cloudflare accepts a fixed set of extra ports that
  all serve the *same site* as `:443`. Counting them separately inflates the estate
  five- to sixfold.

Both stay in the data and can be filtered back in. They are simply kept out of
every headline number.

### The number that matters

On that same estate: **94/100 by endpoint, 48/100 by host** — while 64% of hosts
carried a critical or high finding.

Both are shown, deliberately. **Plan against the host figure**: a host counts once
however many ports it exposes, because a host is the unit of remediation. The
endpoint figure is almost always more flattering, and would have produced a
dangerously reassuring board slide.

When the two diverge, a proxy is multiplying near-identical endpoints. **The gap is
information, not a bug.**

### Confidence is never fudged

| | |
|---|---|
| `confirmed` | The scan data settles it |
| `probable` | Strongly implied, but depends on something not visible from outside |
| `possible` | A fingerprint match. The software *looks* vulnerable; nothing was tested |

A version banner stays `possible` however severe the underlying flaw. Keeping these
apart is what stops the list becoming a wall of maybes nobody trusts.

---

## What you get

Five plain-language sections, not fourteen tabs. **Simple view** shows the first
three; every section has a `?` that explains what it is, how the number is worked
out, and why you should care.

| Section | Answers |
|---|---|
| **Summary** | How big is the estate, how much needs work, is it improving. Printable |
| **What to fix** | Every issue, grouped by rule, ordered by impact, with evidence and remediation |
| **What changed** | What appeared, vanished, or changed since any previous scan |
| **Assets** | **All Assets** — the full grid, every column filterable — plus **Software**, **Network**, **Application**, **Certificates**, **On-Prem**, and **Cloud**: the same searchable table pre-scoped to one category's columns and (where a real boundary exists) rows |
| **Data & setup** | Run scans, manage projects, delete data, and see what the scan could *not* check |

Under the hood: **60 scoring rules** (9 of them v2 correlation rules — dangling
DNS records, bad/shared certificates, shared-hosting exposure), **103 passive
fingerprints** (83 admin consoles grouped by authority, plus default pages and
disclosure checks), and **85 subdomain-takeover providers** — all editable
data, no code.

Exports: a single self-contained HTML file that opens with networking disabled, a
7-sheet spreadsheet, a printable summary, and CI gating via `--fail-on`.

---

## Scanning responsibly

**Analysis is offline.** Ingesting, scoring, diffing, and serving the dashboard
make no network requests at all.

**Three things do reach the network, all explicit:**

| | |
|---|---|
| **Run a scan** in the UI | A real scan of real infrastructure |
| `verify --takeover` | Resolves DNS and issues one GET per candidate. Prompts first |
| subfinder | Queries public passive sources. Sends nothing to the target |

> ### ⚠️ Scan only what you own or have written authorisation to test
> Frogscope asks you to confirm you are authorised and records that you did, but it
> cannot verify it and does not try. Unauthorised scanning is unlawful in many
> jurisdictions.

Subdomain discovery is **passive** — public sources, no DNS brute force, no traffic
to the target. Probing is **active**, and gated accordingly:

- An authorisation checkbox, ticked for every scan — the decision is made once, at
  submission, not asked again mid-run because enumeration turned out bigger than
  expected.
- **`MAX_HOSTS` (200,000)**, a hard, unconditional ceiling. One domain expanded to
  over twenty thousand hosts in testing, and a genuine multi-brand portfolio goes
  well past that — this is the backstop against a target list nobody could have
  intended, not a routine speed bump.
- Rate limit, threads, and timeout bounded server-side. An unbounded rate against
  someone else's estate is a denial of service.
- One scan at a time. Cancellation terminates the process group, so the workers
  stop too — not just the parent.

**Scan options are named choices, never free text.** There is no "extra httpx
arguments" box, deliberately: it would be command injection with extra steps
(`-o /etc/passwd`, `; rm -rf ~`). Options map to an argv *list* built in
`frogscope/scan/options.py`, and subprocesses start without a shell. A flag that is
not in that file cannot be reached from the browser.

### Your data stays where you put it

- Binds to `127.0.0.1`. A single access key (v2) gates every feature — generated
  once on first start (check `docker logs`) or set explicitly via
  `FROGSCOPE_AUTH_KEY`. Share findings by exporting a file, not by exposing a URL —
  the key is a second layer, not a reason to publish the port.
- `data/` and every `*.csv` are gitignored, and CI fails the build if scan data is
  ever tracked.
- Notifications are off by default and need both `notify.yaml: enabled: true` *and*
  `--send`. Webhook URLs come from environment variables, because `config/` is
  committed.

### Sharing outside your team

```bash
frogscope export-html --redact
frogscope workbook --redact
```

Hostnames become salted pseudonyms while the zone structure survives, so
`a.b.acme.com` becomes `h-1a2b.z-3c4d.org-5e6f.example`. Reviewers still see which
hosts share a zone without learning a real name; addresses become RFC 5737
documentation ranges.

Redaction covers dictionary **keys** as well as values — several payload sections
are keyed by endpoint, and an earlier version left over eight thousand hostnames in
plain sight in the keys. Check your own output before sending it:

```bash
grep -c yourdomain.com export.html    # expect 0
```

### Found a vulnerability in Frogscope?

Open a [private security advisory](https://github.com/iamthefrogy/frogscope/security/advisories/new)
rather than a public issue. Particularly interested in: a network request during
ingest, `--redact` leaking a real hostname, argument injection through a domain
name or config value, or a bypass of the SQL column allow-list or the predicate
evaluator.

---

## What it cannot see

Stated plainly, because a clean result from a check that never ran is worse than no
check at all.

- **Nothing behind a path.** No `/.git/config`, no `/.env`, no `/backup.zip`. A
  console at `/admin` on a host whose front page is a marketing site will not be
  found. This is the single largest coverage gap.
- **Nothing is proven exploitable.** A version number is not a vulnerability.
- **Checks with missing data are skipped, never passed.** Certificate rules are
  written and correct; without `-tls-grab` they report as skipped.
- **No email or DNS hygiene.** SPF, DMARC, DKIM and DNSSEC need a resolver step
  that does not exist yet.
- **No screenshots.** `-ss` output is not consumed.

```bash
frogscope catalogue coverage    # quantifies exactly this, per scan
```

---

## Day-to-day use

### Projects

One per target or engagement. Comparisons never cross projects, so a client's
estate cannot contaminate your own history. Create them in the UI — the short name
is derived from what you type.

### Adding scans

Two safety gates, both overridable in one click but never silently:

- **Unfinished scan** — the file looks like it is still being written.
- **Big size change** — more than 30% different from the last scan. If the estate
  really did shrink, accept it. If the scan was cut short, the missing endpoints
  would read as issues that got fixed.

Re-uploading the same file is detected and skipped rather than double-counted.

### Deleting

Three levels, each beside the thing it removes:

| | |
|---|---|
| **One scan** | The `Delete` button on its row in the scan list |
| **One project** | The `Delete <name>` button beside the project selector. Removes the project itself along with every scan, finding, and archived file in it |
| **Everything** | `Delete everything` at the bottom of **Data & setup** |

Each says exactly what will go — "1 scan, 48 endpoint records, 151 findings, 0
saved views, and the archived source files" — and makes you type the name back
before the button enables. The server checks the confirmation too.

Irreversible, and the archived source files go with it — so you cannot re-derive
those scans later even if the analysis improves. Export first if you might want the
data.

---

## Maintenance

### Monthly

```bash
frogscope doctor              # config, dependencies, SQLite features, alert routing
frogscope catalogue coverage  # how much of the catalogue this scan could reach
frogscope rules coverage      # which rules fired, and on how much of the estate
```

`rules coverage` is the one worth actually reading. **A rule firing on nearly every
endpoint is mis-modelled**, not thorough — it warns above 95%.

### Every six months: refresh the detections

```bash
frogscope catalogue status     # when it was last reviewed, and whether it is due
```

Ask your AI assistant: *"Refresh the detection catalogue — follow the procedure in
the README."* That sentence is enough; everything needed is below.

**Nothing depends on nuclei at runtime.** Its templates are read once during a
review and rewritten as our own predicate logic in `config/`. An upstream rename
cannot break anything here — and `config/catalogue.yaml` records what was reviewed,
when, and what was deliberately skipped, so a review never starts from scratch.

<details>
<summary><strong>The refresh procedure</strong> (click to expand)</summary>

#### 1. Establish the baseline

`frogscope catalogue status` prints `last_reviewed` and the upstream counts
observed at that time. The diff against today is what tells you where to look.

#### 2. Pull the current upstream counts

From [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates):
`TEMPLATES-STATS.md` for per-directory counts, and the git tree API for listings.
Compare against `observed` in `config/catalogue.yaml`. **A directory that grew a lot
is where new detections live.** One that barely moved needs a skim, not a review.

#### 3. Review only the ASM-relevant directories

| Upstream | Why it matters | Lands in |
|---|---|---|
| `http/takeovers` | New SaaS providers appear constantly, each a real finding | `config/takeover.yaml` |
| `http/exposed-panels` | New appliance and console families | `config/fingerprints.yaml` → `panels` |
| `ssl` | Small, stable, entirely passive | `config/rules.yaml` → `certificate` |
| `dns` | Dangling-record and SaaS patterns | `takeover.yaml`, `classify.yaml` |
| `http/misconfiguration` | Only the root-page-visible subset | `fingerprints.yaml` |

**Do not review** `http/cves`, `http/vulnerabilities`, `http/exposures`,
`http/fuzzing`, `dast`, `code`, `javascript`, `headless`, `file`,
`http/default-logins`. The reasons are in `catalogue.yaml:excluded` and have not
changed: each needs an active request, a credential attempt, source code, or a
browser. Re-deciding this every time wastes the review.

#### 4. Apply the one test that matters

> **Can this be decided from a scan we already have?**

Available fields: `title`, `webserver`, `tech_names`, `cpe_products`, `cname`,
`status_code`, `port`, `content_length` — plus `body_preview`, `tls_version`,
`cert_*` and `favicon_md5` when the matching flag was used.

- **Yes** → add it.
- **Only with a flag we do not collect** → add it anyway with `requires_fields:`.
  It stays inert, reports as skipped rather than passing, and activates by itself
  the day that flag is used.
- **No** → record it under `excluded` with the reason. A documented gap beats a
  silent one.

#### 5. Write the entries

Takeover provider — `config/takeover.yaml`:

```yaml
- provider: Example SaaS
  cname_suffixes: [example-saas.com]
  body_fingerprints: ['There is no such site']
  claimable: true          # can an outsider register it? decides the grade
  grade: medium            # `high` only with a provider-specific fingerprint
  source: nuclei-templates:http/takeovers
```

Panel — `config/fingerprints.yaml`:

```yaml
- id: PANEL_EXAMPLE
  product: Example Console
  group: infra_console      # decides severity
  title: ['Example Console Login']
  tech: [ExampleProduct]
  require_title: true       # see the warning
  confidence: probable
```

> **`require_title` is the trap.** A technology match means *the site runs this
> platform*, not *the admin panel is reachable*. Matching `tech: [WordPress]` once
> flagged 66 ordinary marketing pages and zero actual admin panels. If the platform
> name does not by itself imply the console is exposed, set `require_title: true`.

#### 6. Verify against real data, not just the tests

```bash
frogscope catalogue validate   # ids unique, regexes compile, groups known
frogscope rules validate
pytest

frogscope ingest <a-real-scan.csv> --project review --label catalogue-check
frogscope rules coverage
frogscope query "panel_product:*" --select host,port,panel_product,title
```

Then **read the matches**, do not just count them. Two failure modes, both of which
have happened:

- **A rule firing on a large fraction of endpoints** — `rules coverage` warns above
  95%. That means mis-modelled, not thorough.
- **Matches whose titles do not support the claim** — this is how the WordPress
  false positive was found. The titles were all marketing copy.

Also watch for regex mistakes: `catalogue validate` rejects a space-padded `|`
(which a regex reads as alternation — `Welcome | PRTG` matched the bare word
"Welcome" and reported a default nginx page as PRTG) and alternatives too short to
be distinctive.

#### 7. Record the review

In `config/catalogue.yaml`: set `last_reviewed` to today, update `observed` with
today's counts, bump `catalogue_version` if detections changed, and add any new
`adopted` or `excluded` entries. Bumping the version is what lets a later score
change be attributed to a catalogue update rather than to the estate moving.

Then `frogscope rescore --all` if scores moved.

#### Other sources worth a look

| Source | Good for |
|---|---|
| `EdOverflow/can-i-take-over-xyz` | Whether a provider is genuinely claimable |
| endoflife.date | EOL dates for `lifecycle.yaml` |
| CISA Known Exploited Vulnerabilities | Which appliance families deserve more weight |
| Wappalyzer / Fingerprintx | Technology fingerprints where httpx is weak |

Add any you adopt to `sources:` in `catalogue.yaml`.

</details>

### After changing a weight or a rule

```bash
frogscope rules validate
frogscope rescore --all
```

Config content is hashed into every run, so a score change can be traced to a
config edit rather than to the estate actually moving.

### Checklist

**Each scan**

- [ ] Read the ingest summary — real endpoints versus artefacts and aliases
- [ ] If a safety gate fired, decide deliberately rather than clicking through
- [ ] Check **Data & setup → What was collected** for what could not be checked
- [ ] Work the **What to fix** list top-down

**Each month**

- [ ] `frogscope doctor`
- [ ] `frogscope rules coverage` — anything above 95% is mis-modelled
- [ ] `frogscope catalogue coverage` — did the last scan use the right flags?
- [ ] Confirm the scan cadence has not quietly lapsed

**Each quarter**

- [ ] Fill in a little more of `ownership.yaml` — it drives the by-team view
- [ ] Review rule weights against what you actually acted on
- [ ] `frogscope store compact --keep-last 12` if the archive is large

**Every six months**

- [ ] Refresh the detection catalogue
- [ ] Re-check `env.custom_keywords` against current naming
- [ ] Confirm a redacted export still leaks nothing

---

## Tuning it for your estate

Eleven config files, all data:

| File | Change it when |
|---|---|
| `classify.yaml` → `env.custom_keywords` | Your naming is not `dev`/`uat`/`prod`. Internal shorthand like `it2ta` goes here, never in the defaults |
| `classify.yaml` → `sensitive_keywords` | Defaults lean finance and general IT. A hospital wants `patient`, a retailer `checkout` |
| `ownership.yaml` | You know which team owns what. Starts empty and the UI says so rather than inventing a split |
| `rules.yaml` | You disagree with a weight |
| `fingerprints.yaml` | You want to detect another product |
| `takeover.yaml` | A new SaaS provider appears |
| `lifecycle.yaml` | New end-of-life dates |
| `ports.yaml` | Different port profiles |
| `notify.yaml` | You want alerts on new findings |
| `columns.yaml` | Grid columns, presets, saved views |
| `catalogue.yaml` | Records what was reviewed, when, and what was skipped |

Config is resolved as `$FROGSCOPE_CONFIG_DIR`, then `./config`, then the checkout —
so you can keep several tuned configs against one install, and data lands beside
whichever config is in use.

---

## Commands

```bash
frogscope init | doctor | config | serve [--host H] [--port N]

frogscope scan TARGET... [--project SLUG] [--authorised]
                         [--approve-hosts N] [--no-subfinder]
                         # targets: domains, IP addresses, and/or CIDR ranges, mixed freely
frogscope ingest FILE [--project SLUG] [--label TEXT]
                      [--allow-incomplete] [--allow-drift] [--force]
frogscope validate FILE            # analyse without writing
frogscope runs                     # list scans
frogscope reindex                  # rebuild diffs and trends
frogscope store verify | compact --keep-last N

frogscope query "env:prod no_waf:yes score:>40"
frogscope findings | report | trends | inventory
frogscope score explain HOST:PORT  # full scoring trace for one endpoint

frogscope rules validate | coverage | list
frogscope rescore [--all]
frogscope catalogue status | coverage | validate | list
frogscope suggest-httpx            # which flags unlock which checks

frogscope export-html [--redact] | workbook [--redact]
frogscope gate --fail-on 'critical>0'      # exit 5 on breach, for CI
frogscope watch DIR [--notify]             # auto-ingest a drop folder
frogscope notify [--send]                  # alert on new findings
frogscope verify --takeover                # sends packets; prompts first
```

Exit codes: `0` fine · `2` usage · `3` duplicate · `4` store integrity · `5`
threshold breached.

---

## v2: cross-asset correlation

Adding domain↔IP↔CIDR↔TLS-cert correlation (dnsx / mapcidr / tlsx), scan
input beyond domains (IP addresses, CIDR ranges), an access-key gate, and
per-project scheduled scanning. Building in phases, each independently
tested before the next starts:

- [x] **Phase 0** — verified real dnsx/mapcidr/tlsx JSON output against
      installed binaries (`tests/fixtures/correlation/`)
- [x] **Phase 1** — data model: `ip_addresses`, `dns_records`, `cidr_blocks`,
      `certificates`, `cert_names`, `cert_observations`, `run_collectors`,
      `schedules` tables (migrations `009`-`013`); new `network` column
      group; `config/cloud_ranges.yaml` (credential-free cloud-range
      detection — no ASN/API-key dependency, see file header for why)
- [x] **Phase 2a** — scan input accepts IP addresses and CIDR ranges, not
      just domains (`frogscope scan 203.0.113.0/24 --authorised`); CIDR
      ranges resolve through mapcidr then dnsx reverse-DNS so named
      endpoints reach httpx wherever a name exists
- [x] **Phase 2b** — dnsx/mapcidr/tlsx wired into the scan pipeline as an
      opt-in "Correlate assets" step (`--correlate` on `frogscope scan`).
      `in_claimable_range`/`dangling_a_record` powered by
      `frogscope/scan/cloud_ranges.py` (AWS/GCP/DigitalOcean live feeds, no
      key required — Azure honestly skipped, see file header). Verified
      end-to-end against real binaries and a live scan; caught and fixed two
      real bugs along the way: dnsx duplicate-line dedup, and cert-to-endpoint
      matching needing (host, port) rather than (host, ip, port) — round-robin
      DNS means httpx and tlsx routinely resolve the same hostname to
      different addresses
- [x] **Phase 3** — 9 new rules (`CERT_SELF_SIGNED`, `CERT_HOSTNAME_MISMATCH`,
      `CERT_WILDCARD_OVERBROAD`, `CERT_COVERS_FOREIGN_DOMAINS`,
      `TLS_WEAK_CIPHER`, `DANGLING_A_RECORD`, `SHARED_HOSTING_FOREIGN`,
      `PTR_MISMATCH`, `POS_CERT_AUTOMATED`); fixed a pre-existing bug found
      along the way (`CERT_EXPIRED`/`CERT_EXPIRING_SOON` had no
      `serves_content` guard, so a dead port with a stale cert scored
      critical); `rules.yaml` bumped to version 2. Verified end-to-end
      against real certs (clean, self-signed) — `CERT_SELF_SIGNED` correctly
      fires as the top finding on a live self-signed endpoint, correctly
      silent on a clean one
- [x] **Phase 4** — `/api/network/summary|ips|cidrs`, `/api/certs`,
      `/api/graph/<kind>/<key>` routes; `/api/endpoints/<key>` extended with
      `network`/`cert`/`same_cert`; `/api/scan/tools`'s `ready` flag fixed to
      reflect only subfinder/httpx (it briefly required all 5 tools, which
      would've reported a plain scan as broken on any machine without
      dnsx/mapcidr/tlsx installed); `store.js` gets matching wrappers, and
      `inventory.js`'s pre-existing raw-`fetch()` bypass (a hole in the
      offline export) is fixed to go through `store.js` like every other
      view. Verified against a real correlated scan via the Flask test client
- [x] **Phase 5** — access-key gate: generated on first container start (not
      at `docker build` — `/data` is a runtime volume, a build-time key would
      bake one identical value into every pulled image and never rotate),
      or set explicitly via `FROGSCOPE_AUTH_KEY`. Every `/api/*` route needs
      an `X-Auth-Key` header except `/api/auth/verify` itself; `/`, `/static/`,
      `/healthz` stay open so the SPA can load far enough to show the
      key-entry screen. "Regenerate key" in Data & setup rotates it (typed
      confirmation), invalidating every other browser immediately while
      keeping the one that triggered it signed in. Found and fixed a real gap
      while wiring the frontend: CSV/Excel export were plain `<a href>`
      downloads, which cannot carry a custom header — converted to
      fetch-then-blob downloads via a new `store.download()`. Verified
      end-to-end (401/200 paths, rotation, persistence across restart)
- [x] **Phase 6** — per-project scheduled scanning (hourly/daily/weekly), in
      **Data & setup → Scans & projects**. A stdlib background thread ticking
      every 60s (no new dependency — see `frogscope/scan/scheduler.py`'s own
      reasoning), gated against Werkzeug's `--reload` double-start. Every
      scheduled run goes through the identical execution path a manual scan
      does (extracted into `frogscope/scan/executor.py` so the two can never
      drift); unattended runs auto-approve up to each schedule's own host cap
      and skip-and-log anything larger, since nobody is there at 3am to click
      "approve". "Run now" fires a schedule immediately for testing. Verified
      end-to-end with real scans (create/list/patch/delete, run-now, and the
      scheduler's own tick() against an overdue schedule)
- [x] **Phase 7** — new tabs: **Network** (Assets, full view only), **Certificates**
      (What to fix), **Newly discovered** (What changed) — `network.js`,
      `certs.js`, `discovered.js`, plus `graph.js`'s `RelationPanel` (a
      sortable table, not an SVG node graph — a wildcard cert or CDN address
      can have thousands of edges, which a force-directed diagram renders as
      an unreadable smear long before a table runs out of room). Drawer gets
      Network/Certificate sections; exec Summary gets exactly 2 new KPIs
      ("assets you didn't know about", "hosts on shared/unrelated
      infrastructure") plus a caveat banner when a run wasn't correlated —
      that caveat is the single most important addition, since without it an
      uncorrelated run silently reads as a complete picture. Verified by
      code review and against the live API; full in-browser check was
      skipped this pass — the shared browser profile was in active use by
      another session and forcing it would have disrupted that work
- [x] **Phase 8** — scan form redesign: one textarea accepts domains, IP
      addresses, and/or CIDR ranges mixed freely, with a live client-side
      breakdown ("12 domains · 3 ranges · 2 not understood") — real
      validation stays server-side (`classify_target()`); "Correlate
      assets" disclosure rendered generically from the server's
      `correlate_steps` catalogue, never hardcoded, with an honestly
      disabled state naming exactly which tools are missing; a CIDR range's
      address count is computed and shown *above* the authorisation
      checkbox, since a prefix length alone doesn't make a range's size
      obvious; "Newly discovered" rows queue into this form via
      `localStorage`, consumed once on mount. Verified end-to-end by posting
      the exact payload shape the form now sends through the real API —
      real scan, real correlation, real DB write

All eight phases are complete. Full in-browser visual verification of the
Phase 7/8 UI was not performed in this pass — the shared browser profile was
in active use by another session throughout, and forcing it would have
disrupted that work. Everything else (every API route, the scoring rules,
the auth gate, the scheduler, and the exact payload shape the redesigned
scan form now sends) was verified end-to-end against the real backend with
real scans. Worth a manual look in an actual browser before calling this
release-ready.

### Since v2: domain-optional scanning, for real

v2 accepted IP/CIDR targets, but DNS/network/TLS correlation stayed opt-in —
meaning an IP-only scan got a bare httpx probe and nothing else unless you found
and ticked "Correlate assets" yourself. Real use surfaced that gap, a crash, and a
few sharper correctness bugs along the way:

- **Fixed a crash**: `UnicodeDecodeError` on IP/CIDR-only scans. A bare address
  with no hostname is far more likely to answer with a default-vhost/no-SNI
  response carrying non-UTF-8 bytes than a named vhost is — `_stream()` now
  decodes with `errors="replace"` instead of the system-locale strict default.
- **DNS/network analysis (dnsx, mapcidr) and TLS certificate reading (tlsx) are
  unconditional now.** Every scan gets all of it, regardless of target kind. The
  "Correlate assets" toggle and everything behind it — `CORRELATE_STEPS`,
  `ScanOptions.correlate`, `correlate_ready()`, the CLI's `--correlate` flag — is
  gone; there was nothing left for it to gate.
- Fixed real correctness gaps this exposed: a CIDR-expanded address whose PTR name
  doesn't itself forward-resolve was silently dropped from network correlation; a
  bare-IP target's generic hosting-provider PTR name was wrongly counted as "ours"
  for foreign-domain findings; `env`/sensitive-keyword classification now falls
  back to a bare-IP record's PTR hostname instead of classifying raw digits.
- **naabu**, port-scanning ahead of httpx and tlsx. Confirmed against the real
  binaries, not assumed: httpx and tlsx both accept `host:port` input lines
  directly, and httpx's `-ports` flag *overrides* rather than defers to one, so
  it's omitted entirely once naabu has scoped the input. tlsx's own target list
  comes from httpx's actual live `scheme==https` results — more accurate than
  naabu's own `tls` field, which reported `false` on a port confirmed serving
  HTTPS in testing. dnsx deliberately stays on the full original target list
  regardless of what naabu/httpx found live: dangling-record and PTR-mismatch
  findings specifically need DNS data for hosts that answer on nothing at all.
  naabu needed its own Debian-based Docker build stage — it links against libpcap
  and can't build with `CGO_ENABLED=0` like every other tool here, and a
  musl-linked (Alpine) CGO binary won't run in the glibc (Debian-slim) runtime
  stage. Found by actually trying the mismatched build, not by assuming it would
  work — same standard as the rest of this section.
- Redesigned **Assets**: "Search everything" → **All Assets**, the unfiltered
  master table, unchanged otherwise. Five new tabs — **Network**, **Application**,
  **Certificates**, **On-Prem**, **Cloud** — are that same searchable table
  pre-scoped to one category's columns, filters, and (where a real boundary exists
  in the data) rows. **Software**'s CPE-products section was removed. "By host",
  the old dedicated Network view, and "Hosting" are unlinked from the tab bar (the
  code stays, just not wired to a tab).
- The interactive "found N hosts, probe all of them?" pause is gone for manual
  scans — `approved_hosts` now defaults to the hard ceiling instead of zero, so a
  scan submitted once stays submitted. `MAX_HOSTS` is still a real, unconditional
  stop against a genuinely runaway target list; scheduled scans are unaffected,
  since they already set their own cap explicitly.
- Removed: the Simple/Full view toggle (the full section list always shows now),
  the scan-count suffix on the project dropdown, the run-picker next to the theme
  toggle.

---

## Architecture

```
domains,   → subfinder/ → naabu       → httpx → correlate:         → normalise → classify → score → store → serve
IPs, CIDRs   mapcidr       (port scan)          dnsx/mapcidr/tlsx        ↑
                                                 (always on)   (or an uploaded CSV — same path from here)
```

**Port scan** (naabu). Scopes what httpx and tlsx bother probing to `host:port`
pairs something actually answers on, using the same port list the chosen profile
would otherwise have probed blindly. Falls back to probing every host across the
whole profile if naabu isn't installed — never blocks a scan.

**Correlate** (dnsx/mapcidr/tlsx — always on, no toggle). Runs after httpx, never
instead of it: dnsx resolves domain↔IP and reverse DNS, mapcidr aggregates the
addresses seen into CIDR blocks, tlsx reads certificates (including other domains
a certificate covers, via SAN) — sourced from httpx's own live `https` results,
not a guessed port. DNS/network analysis runs against every originally-targeted
host regardless of what naabu/httpx found live, deliberately — a dangling DNS
record or a PTR mismatch is exactly the kind of finding that only shows up on a
host answering on nothing. Writes one `correlation.json` sidecar beside the scan
CSV — an upload simply has none, and every field degrades to empty rather than
breaking. No ASN anywhere: asnmap/`dnsx -asn`/mapcidr's ASN input all need a
ProjectDiscovery API key, which this stays independent of —
`frogscope/scan/cloud_ranges.py` answers "which cloud provider owns this address"
from AWS/GCP/DigitalOcean's own public, key-free range feeds instead.

**Normalise.** One row per host and port. Repeat probes collapse into one record,
and DNS answers are unioned rather than last-write — otherwise round-robin DNS
reports a change every week. Identity is the *hostname*, never the resolved
address, which would rotate.

**Classify.** Response class, environment, zone, what is in front of it, and any
product identified. This is where noise gets separated from signal.

**Score.** Rules carry a weight, a severity, a confidence, and the text explaining
themselves. Scores cap per category, near-duplicate rules de-duplicate, and
mitigations reduce but never erase a serious finding.

**Store.** SQLite. Each scan is a run; runs are diffed against each other. The
source file is archived, so if the analysis improves you can re-ingest an old scan
and get the better answer.

```
config/          eleven YAML files — every tunable, plus cloud_ranges.yaml (v2)
examples/        demo-scan.csv — synthetic, safe to ingest
frogscope/       the application
  scan/            the only code that drives the scanners, and the only
                   place (with verify/) allowed to touch the network —
                   including cloud_ranges.py's cloud-range feed fetch
  ingest/          correlate.py: v2 sidecar parsing — reads the network's
                   output, never touches the network itself
  api/             Flask JSON API
  static/app/      vendored Preact SPA — no build step
Dockerfile       three stages: Go builds the pure-static scanners, a separate
                 Debian-based stage builds naabu (needs CGO/libpcap, so it can't
                 be pure-static like the rest), Python runs the app
data/            gitignored: database plus archived source files
tests/           546 tests
```

```bash
.venv/bin/pytest
.venv/bin/ruff check frogscope tests
```

---

## Contributing

Issues and pull requests welcome. Most useful changes are **data, not code** —
detections, weights, and classifications all live in `config/`.

Three house rules:

1. **Nothing may send a packet during ingest.** `frogscope/scan/` and
   `frogscope/verify/` are the only networking code.
2. **A check that cannot run must be reported, never passed.** Use
   `requires_fields:`.
3. **A technology match is not an exposed panel.** Matching `tech: [WordPress]`
   once flagged 66 ordinary marketing pages and zero admin panels. Set
   `require_title: true` when the platform name does not imply the console is
   reachable.

Before opening a PR: `ruff check frogscope tests`, `pytest`, `frogscope doctor`,
`rules validate`, `catalogue validate` — then ingest `examples/demo-scan.csv` and
*look at* the result. Assert invariants in tests, never hardcoded row counts.

## Licence

MIT — see [LICENSE](LICENSE).
