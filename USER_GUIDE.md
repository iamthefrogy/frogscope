# Frogscope

## What it is

Frogscope points at your internet-facing estate — domains, IP addresses, or
address ranges — and tells you three things:

1. **What's actually out there.** Every reachable host, port, certificate, and
   piece of DNS data, correlated together.
2. **What needs fixing**, in plain English, ranked by how much it matters.
3. **What changed** since the last time you scanned.

Everything runs from one Docker container. No cloud account, no per-asset
pricing, no sending your asset list to a third party.

## Why this exists

Most external-scanning tools do one of two things badly: they either flood you
with thousands of "findings" that are actually the same proxy port counted
thirteen times, or they need a heavyweight platform and a support contract to
run at all.

Frogscope was built to do the boring part right — tell a real exposed service
apart from scan noise, tell a domain you own apart from one that just happens
to share a certificate — so the list you're staring at on a Monday morning is
short enough to actually work through.

## How it's different

- **Counts services, not rows.** A Cloudflare-fronted site answering on
  thirteen proxy ports is one service, not thirteen findings.
- **Never guesses at severity from a version banner.** Every finding is
  labelled `confirmed`, `probable`, or `possible` — a fingerprint match stays
  `possible` no matter how scary the underlying flaw sounds.
- **Analysis never touches the network.** Only the scan step does. Scoring,
  diffing, and everything you click through in the UI runs entirely offline
  against data already collected.
- **Takes domains, IPs, and CIDR ranges — mixed freely, one scan.** Not domains
  only. DNS, network, and TLS certificate correlation run automatically, on
  every scan, regardless of what you fed it.
- **Every detection is an editable config file, not code.** Scoring weights,
  fingerprints, takeover providers, environment keywords — all in `config/`.
  Tune it for your estate without touching Python.
- **Honest about what it can't see.** A dashboard that goes quiet about its own
  blind spots is worse than no dashboard — Frogscope tells you outright what a
  scan did and didn't check.

## Who uses it, and for what

**Pentest / Red team** — recon before an engagement. Point it at the client's
domains and IP ranges, get the full attack surface in one pass: forgotten
subdomains, exposed admin panels and management consoles, subdomain-takeover
candidates, weak/default certificates. Use the findings list as your initial
target shortlist, export a workbook for the report.

**SecOps** — continuous exposure monitoring. Schedule recurring scans per
project, and use **What changed** to see exactly what appeared, vanished, or
shifted since last time — new host, new open port, a cert that flipped to
self-signed. Feed alerts to your existing tooling via webhook.

**AppSec** — track what's actually running. Technology and web-server
inventory, end-of-life software, version disclosure, default/parked pages —
all searchable and filterable in **Assets → Software** and **Application**.
Turns "what's our exposure to CVE-X" from a Slack thread into a filtered grid.

**Vulnerability Management** — the asset inventory you need before you can even
scan for vulnerabilities. "What do we actually have on the internet" is
usually the hardest part of a VM program to answer honestly — Frogscope answers
it, with ownership tagging and a risk score to help prioritize what a
traditional vuln scanner should look at first.

## Install with Docker

You need Docker and Docker Compose. Nothing else.

```bash
git clone https://github.com/iamthefrogy/frogscope
cd frogscope
docker compose up --build
```

Watch the logs for a line like:

```
Frogscope access key (save this): yLA8CX7N-T3BWYZN-wwVQUN3y-HFSRirvk6O3Z7dY74
```

Copy that key — it's generated once, the first time the container starts, and
never printed again. You'll paste it into the browser on first visit.

Open **http://127.0.0.1:8099**, paste the key, and you're in.

That's the whole install. Your data lives in a Docker volume and survives
restarts; `./config` is mounted from your checkout so any tuning survives a
rebuild.

## Using the UI

### 1. Create a project, run a scan

A **project** is one target — a client engagement, your own company, a
business unit. Create one, then paste your targets into the scan box: domains,
IP addresses, or CIDR ranges, one per line or comma-separated, mixed freely.

```
acme.com
acme.co.uk
203.0.113.0/24
198.51.100.42
```

Tick the authorisation checkbox (you're confirming you're allowed to scan
these), press **Start scan**, and wait. A scan enumerates subdomains, port-scans,
probes what's live, and pulls DNS/network/TLS data automatically — no extra
toggles to remember.

### 2. The five sections

| Section | What it's for |
|---|---|
| **Summary** | The board-level view — how big the estate is, what's improving, what's not. Printable. |
| **What to fix** | Every issue, ranked by severity, with evidence and how to fix it. Start here day-to-day. |
| **What changed** | New, gone, or modified since any previous scan of this project. |
| **Assets** | Everything the scan found, organized by category — see below. |
| **Data & setup** | Run/manage scans and projects, set up scheduled scanning, see what a scan could and couldn't check. |

### 3. Assets — one master table, seven views

**All Assets** is the master table — every host, every column, fully
filterable and searchable. Everything else in this section is that same table,
pre-filtered to one slice of it, so you're never looking at a different data
source, just a narrower view:

- **Software** — what's running: web servers, detected technologies,
  end-of-life products, WordPress plugins.
- **Network** — IPs, DNS records, PTR data, CIDR blocks, dangling-record
  candidates.
- **Application** — the runtime side: status codes, titles, redirects, exposed
  panels.
- **Certificates** — TLS certs: expiry, self-signed, mismatched, wildcard
  scope, what other domains a cert covers.
- **On-Prem** / **Cloud** — the same assets split by whether they sit behind a
  known cloud/CDN provider or not.

Click any row to open the drawer — full detail for that one endpoint,
including related hosts sharing the same IP or certificate.

### 4. Scheduled scanning

In **Data & setup**, set up a recurring scan per project — hourly, daily, or
weekly. Useful for anything meant to stay watched continuously rather than
scanned once and forgotten.

### 5. Exporting

- **CSV / Excel** — from any Assets view, respects your current filter.
- **Printable summary** — from the Summary section.
- A scan run through the UI and a CSV you uploaded produce identical results —
  mix both in one project freely.

## One thing to remember

Frogscope asks you to confirm you're authorised to scan a target and records
that you did — it does not and cannot verify it. Only scan what you own or
have explicit written permission to test.