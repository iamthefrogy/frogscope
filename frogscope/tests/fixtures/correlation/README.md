# Correlation collector fixtures (Phase 0)

Real `-json` output captured directly from installed binaries against public,
intentionally-scannable targets (`example.com`, and badssl.com's dedicated
test-certificate subdomains). No third-party production systems touched —
badssl.com exists specifically to be probed for expired/self-signed/mismatched
cert testing.

## Tool versions (pin these — schema can shift between releases)

- dnsx: `1.2.2` (`/usr/local/bin/dnsx`)
- mapcidr: `v1.1.97` (`~/.pdtm/go/bin/mapcidr`)
- tlsx: `v1.2.2` (`~/.pdtm/go/bin/tlsx`)

## Files

| File | Command | Notes |
|---|---|---|
| `dnsx_resolve.jsonl` | `dnsx -a -aaaa -cname -j -duc` | domain -> IP |
| `dnsx_ptr.jsonl` | `dnsx -ptr -j -duc` | IP -> domain (reverse) |
| `mapcidr_expand.txt` | `mapcidr -cidr <cidr>` | CIDR -> IP, **no `-json` flag exists** |
| `mapcidr_aggregate.txt` | `mapcidr -aggregate` | IP/CIDR list -> minimal covering CIDR |
| `tlsx_domain.jsonl` | `tlsx -ex -ss -mm -un -hash=sha256 -jarm -j -duc` | clean cert (example.com) |
| `tlsx_expired.jsonl` | same, `-timeout 10` | `"expired":true` (also `"revoked":true` — see below) |
| `tlsx_selfsigned.jsonl` | same | `"self_signed":true` |
| `tlsx_mismatched.jsonl` | same | `"mismatched":true` |
| `tlsx_bareip.jsonl` | `tlsx -rps -ex -ss -mm -un -hash=sha256 -j -duc` | bare IP, no hostname |

## Confirmed field names (do not guess, this is read from real stdout)

**dnsx** (lowercase, no hyphens for the fields we use — `-asn`/`-cdn` were
NOT tested, out of scope per the ASN/PDCP-key decision):
`host, ttl, resolver[], a[], aaaa[], cname[]?, ptr[]?, soa[], status_code
("NOERROR"|"NXDOMAIN"|...), raw_resp{...}, timestamp`.

- `ptr` key is **absent entirely** on NXDOMAIN (no reverse record) — not an
  empty array. Test for key presence, don't assume `[]`.
- **dnsx emits duplicate identical JSONL lines per host** in these captures
  (seen consistently on both the resolve and PTR runs) — likely one line per
  resolver race that returned first, or a retry artifact. `ingest/correlate.py`
  must dedupe by `host` (or `(host, a, aaaa)` tuple) before writing rows, or
  every IP's hostname_count/foreign_name_count will double-count.
- Cloudflare-fronted IPs return `NXDOMAIN` on PTR (no reverse DNS) — this is
  normal for CDN/anycast ranges, not a data-quality problem. Don't flag CDN IPs
  for `ptr_missing`-driven findings without a CDN check first (ties into the
  existing `cdn_name` column already in `enrich.py`).

**mapcidr** — confirmed **no `-json` output mode exists at all**. Plain
line-oriented stdout: one IP per line for expand (includes network/broadcast
addresses unless `-skip-base -skip-broadcast` passed), one CIDR per line for
aggregate, a bare integer for `-count`, echoes the IP back (or prints nothing)
for `-match-ip`. Parser must be `.strip().splitlines()`, never a JSON decoder.

**tlsx** — confirmed field names, all snake_case:
`timestamp, host, ip, port, probe_status, tls_version, cipher, not_before,
not_after, subject_dn, subject_cn, subject_org[]?, subject_an[], serial,
issuer_dn, issuer_cn, issuer_org[], fingerprint_hash{md5,sha1,sha256},
wildcard_certificate, tls_connection, sni, client_cert_required?` plus
**boolean misconfig keys that are omitted entirely when false** (Go
`omitempty`): `expired`, `self_signed`, `mismatched`, `revoked`. **Test for key
presence (`"expired" in record`), never `record.get("expired")` truthiness on
a default — there is no default, the key just isn't there.**

- **`expired.badssl.com` also came back `"revoked":true`** alongside
  `"expired":true` — an expired cert can trip more than one misconfig flag at
  once; don't treat these as mutually exclusive in the schema or the scoring
  rules.
- **`-san` and `-cn` cannot be combined with any other PROBES-group flag**
  (`-so`, `-tv`, `-cipher`, `-ex`, `-ss`, `-mm`, `-jarm`, `-wc` all conflict —
  confirmed by bisection; only `-un` didn't error, inconsistently) — tlsx v1.2.2
  fails validation with `"san or cn flag cannot be used with other probes"`.
  **This doesn't cost anything**: in `-json` mode, `subject_an`/`subject_cn`
  are already present in *every* response regardless of which probe flags are
  passed (confirmed: a run with zero probe flags returns the identical full
  record). **`options.py`'s `tlsx_argv()` must never pass `-san`/`-cn` at
  all** — just `-j` plus the misconfig/hash/jarm flags gets everything.
  `-so`/`-tv`/`-cipher` are likewise redundant (already in the JSON) but don't
  conflict with each other or with `-ex`/`-ss`/`-mm`/`-un`/`-hash`/`-jarm` —
  only `-san`/`-cn` are special-cased.
- **`-hash` requires `=` syntax**: `-hash=sha256` works, `-hash sha256` (space)
  fails with `flag provided but not defined: -hash sha256`. Argv builder must
  emit it as one token `-hash=sha256`, not two argv elements.
- **Bare-IP scanning without a resolvable PTR returns whatever default vhost
  cert answers** on that IP, not necessarily anything meaningful — seen
  directly: probing badssl.com's shared IP with no SNI returned a literal
  "BadSSL Fallback. Unknown subdomain or no SNI." certificate (also flagged
  expired+self-signed+mismatched+revoked, since it's a deliberately broken
  demo cert). `-rps` (reverse-PTR SNI) made no difference here because that
  particular IP has no PTR record either — so `-rps` is worth keeping in the
  real argv builder, but `enrich.py` must not treat a bare-IP cert grab as
  authoritative for "the certificate this hostname presents" — it's "the
  certificate this IP's default vhost presents," which can be a different
  thing entirely on shared/multi-tenant hosting.
