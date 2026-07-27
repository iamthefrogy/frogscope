#!/usr/bin/env python3
"""Generate the committed example scan.

Entirely synthetic — RFC 5737 addresses, RFC 2606 domains. It exists so that a
new user, and CI, can see the tool do something real without needing a target of
their own to scan.

It is written to exercise the interesting paths rather than to look tidy:

* a Cloudflare-fronted host answering on every alias port, so the artefact and
  alias arithmetic has something to collapse
* a TLS-only port probed over cleartext, which is the single largest noise source
  in a real scan
* an exposed console of each authority level
* a dangling-record candidate, and a broken-origin host that must NOT be reported
  as one
* end-of-life software, a plain-HTTP login, and a WAF that is bypassable on a
  second port

Regenerate with:  python3 tools/make_demo_scan.py
"""
from __future__ import annotations

import csv
import json
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "examples" / "demo-scan.csv"

# The subset of httpx's CSV columns this demo populates. Absent columns are
# handled by the loader as missing rather than empty, which is itself worth
# exercising.
COLUMNS = [
    "timestamp", "port", "url", "input", "title", "scheme", "webserver",
    "content_type", "method", "host", "path", "time", "a", "aaaa", "cname",
    "tech", "words", "lines", "status_code", "content_length", "failed",
    "cdn_name", "cdn_type", "cdn", "final_url", "resolvers", "body_preview",
]

CF_HTTP = [80, 2052, 2082, 2086, 2095, 8080, 8880]
CF_HTTPS = [443, 2053, 2083, 2087, 2096, 8443]
TLS_ONLY = {443, 2053, 2083, 2087, 2096, 8443}

ARTEFACT_TITLE = ("400 The plain HTTP request was sent to HTTPS port")

rows: list[dict] = []
stamp_n = 0


def add(host, port, *, status=200, title="", scheme="https", server="",
        tech="", cdn="", cdn_type="", cname="", ip="198.51.100.10",
        ctype="text/html", body="", final="", length=1024):
    global stamp_n
    stamp_n += 1
    minute, second = divmod(stamp_n * 7, 60)
    rows.append({
        "timestamp": f"2026-03-02T09:{minute % 60:02d}:{second:02d}.000000+00:00",
        "port": port,
        "url": f"{scheme}://{host}:{port}",
        "input": f"{scheme}://{host}:{port}",
        "title": title,
        "scheme": scheme,
        "webserver": server,
        "content_type": ctype,
        "method": "GET",
        "host": host,
        "path": "/",
        "time": "241.5ms",
        "a": json.dumps([ip]) if ip else "",
        "aaaa": "",
        "cname": json.dumps([cname]) if cname else "",
        "tech": json.dumps(tech.split("|")) if tech else "",
        "words": 120,
        "lines": 20,
        "status_code": status,
        "content_length": length,
        "failed": "false",
        "cdn_name": cdn,
        "cdn_type": cdn_type,
        "cdn": "true" if cdn else "false",
        "final_url": final or f"{scheme}://{host}:{port}/",
        "resolvers": json.dumps(["203.0.113.1:53"]),
        "body_preview": body,
        })


# ── A Cloudflare-fronted marketing site ─────────────────────────────────────
# Answers on every alias port. Thirteen rows, one service. This is the arithmetic
# that makes a real estate look several times larger than it is.
for port in CF_HTTP:
    add("www.example.com", port, title="Example Corp — Home", scheme="http",
        server="cloudflare", cdn="cloudflare", cdn_type="waf",
        cname="www.example.com.cdn.cloudflare.net", ip="198.51.100.1")
for port in CF_HTTPS:
    add("www.example.com", port, title="Example Corp — Home",
        server="cloudflare", cdn="cloudflare", cdn_type="waf",
        cname="www.example.com.cdn.cloudflare.net", ip="198.51.100.1")

# Cleartext probes of TLS-only ports: correct server behaviour, not a finding.
for port in sorted(TLS_ONLY - {443}):
    add("shop.example.com", port, status=400, title=ARTEFACT_TITLE, scheme="http",
        server="cloudflare", cdn="cloudflare", cdn_type="waf", ip="198.51.100.2")
add("shop.example.com", 443, title="Example Shop", server="cloudflare",
    cdn="cloudflare", cdn_type="waf", tech="Cloudflare|WordPress",
    ip="198.51.100.2")

# ── Exposed consoles, one per authority level ──────────────────────────────
add("ci.example.com", 8080, title="Dashboard [Jenkins]", scheme="http",
    server="Jetty(9.4.z-SNAPSHOT)", tech="Jenkins|Java",
    ip="198.51.100.20", body="Welcome to Jenkins!")
add("k8s.example.com", 443, title="Kubernetes Dashboard",
    tech="Kubernetes", ip="198.51.100.21")
add("db-admin.example.com", 443, title="phpMyAdmin", server="Apache/2.4.41",
    tech="PHP|Apache HTTP Server", ip="198.51.100.22", body="pma_username")
add("metrics.example.com", 3000, title="Grafana", tech="Grafana",
    ip="198.51.100.23")
add("vpn.example.com", 443, title="GlobalProtect Portal", ip="198.51.100.24")
add("mail.example.com", 443, title="Outlook Web App", server="Microsoft-IIS/10.0",
    ip="198.51.100.25")

# ── A dangling-record candidate ────────────────────────────────────────────
# CNAME to a provider that allows re-registration, and the provider is serving its
# "no such resource" page.
add("blog-old.example.com", 443, status=404, title="Web App - Unavailable",
    cname="blog-old-prod.azurewebsites.net", ip="", body="Web App - Unavailable")

# A broken origin, which looks similar and must NOT be graded as a takeover: the
# origin exists, its TLS is simply misconfigured.
add("legacy.example.com", 443, status=525, title="", server="cloudflare",
    cdn="cloudflare", cdn_type="waf", cname="legacy.example.com.cdn.cloudflare.net",
    ip="198.51.100.3")

# And an origin that genuinely resolves to nothing — Cloudflare error 1016.
add("gone.example.com", 443, status=530, title="", server="cloudflare",
    cdn="cloudflare", cdn_type="waf", ip="198.51.100.4")

# ── End-of-life software, reachable ────────────────────────────────────────
add("legacy-app.example.com", 80, title="Intranet Portal", scheme="http",
    server="Microsoft-IIS/6.0", tech="IIS|Windows Server 2003",
    ip="198.51.100.30")

# ── A login page served over plain HTTP, with no upgrade ───────────────────
add("portal.example.com", 80, title="Sign in", scheme="http",
    server="nginx/1.18.0", tech="nginx", ip="198.51.100.31")

# ── A WAF that can be side-stepped on a second port ────────────────────────
add("api.example.com", 443, title="API Gateway", server="cloudflare",
    cdn="cloudflare", cdn_type="waf", ctype="application/json",
    cname="api.example.com.cdn.cloudflare.net", ip="198.51.100.5")
add("api.example.com", 8443, title="API Gateway", server="nginx/1.20.1",
    ctype="application/json", ip="203.0.113.55")

# ── Non-production, reachable ─────────────────────────────────────────────
add("uat-portal.example.com", 443, title="Example Portal (UAT)",
    server="nginx/1.20.1", tech="nginx|React", ip="198.51.100.40")
add("dev.example.com", 443, title="Example Dev", server="nginx/1.20.1",
    ip="198.51.100.41")

# ── Default install pages: nobody finished the job ────────────────────────
add("new1.example.com", 443, title="IIS Windows Server",
    server="Microsoft-IIS/10.0", ip="198.51.100.50")
add("new2.example.com", 443, title="Welcome to nginx!", server="nginx/1.18.0",
    ip="198.51.100.51")

# ── Directory listing, and a stack trace ─────────────────────────────────
add("files.example.com", 443, title="Index of /", server="Apache/2.4.41",
    ip="198.51.100.52")
add("app-broken.example.com", 443, status=500, title="Whitelabel Error Page",
    tech="Spring", ip="198.51.100.53")

# ── Shared hosting: a concentration question as much as a security one ───
for n in range(1, 9):
    add(f"site{n}.example.com", 443, title=f"Site {n}", server="nginx/1.20.1",
        ip="198.51.100.100")

# ── A host answering on a genuinely non-standard port ────────────────────
add("app-server.example.com", 7001, title="Oracle WebLogic Server",
    scheme="http", ip="198.51.100.60")

# ── Something with nothing at all in front of it ─────────────────────────
add("direct.example.com", 443, title="Internal Tools", server="Apache/2.4.41",
    ip="203.0.113.77")

OUT.parent.mkdir(parents=True, exist_ok=True)
with OUT.open("w", newline="", encoding="utf-8") as fh:
    writer = csv.DictWriter(fh, fieldnames=COLUMNS)
    writer.writeheader()
    writer.writerows(rows)

hosts = len({r["host"] for r in rows})
print(f"wrote {OUT} — {len(rows)} rows across {hosts} hosts")
