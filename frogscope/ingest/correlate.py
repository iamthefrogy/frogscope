"""Attach v2 correlation data (dnsx / mapcidr / tlsx) onto records, and build
the relational entity lists that back the Network and Certificates views.

Kept separate from `schema.py`, which is specifically the httpx-CSV field
registry — this is a different source shape entirely: JSONL from three
different tools, whose exact field names were verified against real installed
binaries rather than trusted from README prose (see
tests/fixtures/correlation/README.md for what was checked and why it
mattered — dnsx's duplicate-line behaviour and tlsx's omitted-when-false
booleans both live there).

No ASN handling anywhere in this module, by design: asnmap, `dnsx -asn`, and
mapcidr's `ASxxxx` input all require a ProjectDiscovery API key, which this
release does not depend on. `in_claimable_range`/`dangling_a_record` are
powered by `config/cloud_ranges.yaml` instead — see that file and
`frogscope/scan/cloud_ranges.py` for how the credential-free replacement
works. This module only ever READS the local cache that fetch step writes;
it never touches the network itself (see the "Nothing may send a packet
during ingest" house rule in the README).
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from .normalize import is_address, registrable_domain

IP_KEY_WIDTH = 32  # hex chars — a v6 address is 128 bits

# Coarse, deliberately simple: enough to separate "fine" from "renegotiate
# this", not a full cipher-suite audit.
_INSECURE_CIPHER_MARKERS = ("RC4", "DES", "3DES", "NULL", "EXPORT", "MD5", "ANON")
_WEAK_CIPHER_MARKERS = ("CBC",)


def ip_sort_key(ip: str) -> str:
    return format(int(ipaddress.ip_address(ip)), f"0{IP_KEY_WIDTH}x")


def cipher_grade(cipher: str) -> str:
    upper = (cipher or "").upper()
    if not upper:
        return ""
    if any(marker in upper for marker in _INSECURE_CIPHER_MARKERS):
        return "insecure"
    if any(marker in upper for marker in _WEAK_CIPHER_MARKERS):
        return "weak"
    return "secure"


def _parse_dt(value: str | None) -> datetime | None:
    """Always naive UTC, regardless of whether the source string carried a
    timezone offset — tlsx's timestamps do, `pipeline._window()`'s scanned_at
    values do not, and subtracting an aware datetime from a naive one raises
    rather than compares."""
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is not None:
        dt = dt.astimezone(UTC).replace(tzinfo=None)
    return dt


@dataclass
class Correlation:
    """The raw sidecar, parsed but not yet cross-referenced."""

    dns: list[dict] = field(default_factory=list)     # dnsx resolve records
    ptr: list[dict] = field(default_factory=list)      # dnsx PTR records
    tls: list[dict] = field(default_factory=list)      # tlsx records
    cidrs_aggregated: list[str] = field(default_factory=list)
    scan_cidrs: list[str] = field(default_factory=list)  # what was actually targeted
    collectors: dict[str, dict] = field(default_factory=dict)
    reference_time: str | None = None  # this run's scan time, for cert age/expiry
    scan_domains: list[str] = field(default_factory=list)  # explicitly entered, not enumerated
    # Hostnames that exist ONLY because a bare IP/CIDR target had no name of
    # its own and got one via reverse-DNS fallback (see
    # `scan/runner.py::_resolve_ip_cidr_targets`) — never user-entered, never
    # subfinder-found. Usually a hosting provider's generic PTR label.
    ptr_resolved_hosts: list[str] = field(default_factory=list)


def domains_from_records(records: list[dict], multi_label_tlds=(),
                         ptr_resolved_hosts: frozenset[str] = frozenset(),
                         explicit_domains: frozenset[str] = frozenset()) -> set[str]:
    """"Ours" for correlation purposes: the registrable domain of every host
    this run actually probed, seeded first with the domains the scan
    explicitly targeted.

    A host in `ptr_resolved_hosts` is excluded from the record-derived half —
    a bare IP/CIDR target that only got a name via reverse-DNS fallback
    (often a hosting provider's generic PTR label, e.g.
    `5-113-0-203.static.provider.net`) is not something the user owns, and
    counting it as "ours" would wrongly suppress foreign-domain/shared-
    hosting findings for exactly the IP-only scans that most need them. It
    still counts if the same registrable domain also appears in
    `explicit_domains` — reverse-resolving to a domain the user actually
    entered is a real, corroborated match, not a fallback guess.
    """
    out: set[str] = {registrable_domain(d, multi_label_tlds) for d in explicit_domains}
    for rec in records:
        host = rec.get("host") or ""
        if not host or is_address(host) or host in ptr_resolved_hosts:
            continue
        out.add(registrable_domain(host, multi_label_tlds))
    return out


def ptr_map(corr: Correlation) -> dict[str, str]:
    """ip -> first PTR hostname, read straight off the raw sidecar. Kept
    independent of `build_entities()`/`attach()` so it can run before
    `enrich.enrich()` — attach() must run AFTER enrich() (`dangling_a_record`
    needs `serves_content`), but env/sensitivity classification wants a
    bare-IP record's PTR name BEFORE enrich() runs, since that's where those
    fields get set. Two different consumers, two different orderings — this
    helper is what lets both be satisfied without entangling the two passes.
    """
    out: dict[str, str] = {}
    for rec in corr.ptr:
        ip = (rec.get("host") or "").strip()
        ptr = rec.get("ptr") or []
        if ip and ptr and ip not in out:
            out[ip] = str(ptr[0]).rstrip(".").lower()
    return out


def load(raw: dict | str | Path) -> Correlation:
    if isinstance(raw, (str, Path)):
        raw = json.loads(Path(raw).read_text(encoding="utf-8"))
    return Correlation(
        dns=raw.get("dns") or [],
        ptr=raw.get("ptr") or [],
        tls=raw.get("tls") or [],
        cidrs_aggregated=(raw.get("cidrs") or {}).get("aggregated") or [],
        scan_cidrs=raw.get("scan_cidrs") or [],
        collectors=raw.get("collectors") or {},
        reference_time=raw.get("reference_time"),
        scan_domains=raw.get("scan_domains") or [],
        ptr_resolved_hosts=raw.get("ptr_resolved_hosts") or [],
    )


@dataclass
class Entities:
    ip_addresses: list[dict] = field(default_factory=list)
    dns_records: list[dict] = field(default_factory=list)
    cidr_blocks: list[dict] = field(default_factory=list)
    certificates: list[dict] = field(default_factory=list)
    cert_names: list[dict] = field(default_factory=list)
    cert_observations: list[dict] = field(default_factory=list)


def load_cached_ranges(cache_path: Path,
                       provider_ids: list[str]) -> dict[str, list] | None:
    """Read the cloud-range cache `scan/cloud_ranges.py` wrote. Pure file I/O
    — no network call lives here, matching the ingest-is-offline rule.
    Returns None if the cache doesn't exist yet (never fetched)."""
    if not cache_path.exists():
        return None
    try:
        raw = json.loads(cache_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    out: dict[str, list] = {}
    for pid in provider_ids:
        entry = (raw.get("providers") or {}).get(pid) or {}
        nets = []
        for cidr in entry.get("cidrs") or []:
            try:
                nets.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                continue
        if nets:
            out[pid] = nets
    return out


def _claimable_provider(ip: str, ranges: dict[str, list] | None) -> str:
    if not ranges:
        return ""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ""
    for provider_id, networks in ranges.items():
        for net in networks:
            if addr in net:
                return provider_id
    return ""


def build_entities(corr: Correlation, *, our_domains: set[str],
                   multi_label_tlds=(), known_names: set[str] = frozenset(),
                   cloud_ranges: dict[str, list] | None = None) -> Entities:
    """our_domains: registrable domains this scan targeted (the seed of
    "ours"). known_names: every hostname/domain seen in ANY prior run of this
    project, so a cert SAN can be flagged `discovered_new`."""
    ent = Entities()
    reference_time = _parse_dt(corr.reference_time) or datetime.now(UTC).replace(tzinfo=None)

    def is_ours(name: str) -> bool:
        if not name or is_address(name):
            return False
        return registrable_domain(name, multi_label_tlds) in our_domains

    # ── DNS records: forward (A/AAAA/CNAME) ─────────────────────────────────
    dns_rows: list[dict] = []
    for rec in corr.dns:
        host = (rec.get("host") or "").rstrip(".").lower()
        if not host:
            continue
        for rtype, key in (("A", "a"), ("AAAA", "aaaa")):
            for ip in rec.get(key) or []:
                dns_rows.append({
                    "name": host, "record_type": rtype, "value": str(ip).strip(),
                    "ttl": rec.get("ttl"), "source": "dnsx",
                    "in_scope": is_ours(host),
                })
        for pos, target in enumerate(rec.get("cname") or []):
            target = str(target).rstrip(".").lower()
            if target:
                dns_rows.append({
                    "name": host, "record_type": "CNAME", "value": target,
                    "ttl": rec.get("ttl"), "chain_pos": pos, "source": "dnsx",
                    "in_scope": is_ours(host),
                })

    # ── DNS records: reverse (PTR) ───────────────────────────────────────────
    # Modelled the same direction as A/AAAA (name=hostname, value=IP) so one
    # index (idx_dns_rev on `value`) answers "what points at this IP" whether
    # the edge was discovered forward or in reverse.
    ptr_by_ip: dict[str, list[str]] = {}
    for rec in corr.ptr:
        ip = (rec.get("host") or "").strip()
        if not ip:
            continue
        names = [str(n).rstrip(".").lower() for n in (rec.get("ptr") or [])]
        bucket = ptr_by_ip.setdefault(ip, [])
        for name in names:
            if name not in bucket:
                bucket.append(name)
            dns_rows.append({
                "name": name, "record_type": "PTR", "value": ip,
                "ttl": rec.get("ttl"), "source": "dnsx", "in_scope": is_ours(name),
            })

    # dnsx emits duplicate identical lines per host (confirmed against real
    # output, see fixtures README) — dedupe on the natural key before writing.
    seen_dns: set[tuple] = set()
    for row in dns_rows:
        key = (row["name"], row["record_type"], row["value"])
        if key in seen_dns:
            continue
        seen_dns.add(key)
        ent.dns_records.append(row)

    # ── IP addresses ─────────────────────────────────────────────────────────
    names_by_ip: dict[str, set[str]] = {}
    for row in ent.dns_records:
        if row["record_type"] in ("A", "AAAA", "PTR"):
            names_by_ip.setdefault(row["value"], set()).add(row["name"])

    all_ips = set(names_by_ip) | set(ptr_by_ip)
    for tls_rec in corr.tls:
        ip = tls_rec.get("ip")
        if ip:
            all_ips.add(ip)

    for ip in all_ips:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        names = names_by_ip.get(ip, set())
        ours = {n for n in names if is_ours(n)}
        foreign = names - ours
        foreign_domains = {
            registrable_domain(n, multi_label_tlds) for n in foreign
            if not is_address(n)
        }
        claimable = _claimable_provider(ip, cloud_ranges)
        ent.ip_addresses.append({
            "ip": addr.compressed, "ip_version": addr.version,
            "ip_sort_key": ip_sort_key(ip), "is_private": addr.is_private,
            "ptr_count": len(ptr_by_ip.get(ip, [])),
            "ptr_primary": (ptr_by_ip.get(ip) or [None])[0],
            "ptr": ptr_by_ip.get(ip) or [],
            "hostname_count": len(ours), "endpoint_count": 0,
            "foreign_name_count": len(foreign),
            "foreign_domain_count": len(foreign_domains),
            "in_claimable_range": bool(claimable),
            "claimable_provider": claimable,
            "discovered_via": "dnsx",
        })

    # ── CIDR blocks ──────────────────────────────────────────────────────────
    for cidr in set(corr.scan_cidrs) | set(corr.cidrs_aggregated):
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        observed = sum(
            1 for ip in all_ips
            if ipaddress.ip_address(ip).version == net.version
            and ipaddress.ip_address(ip) in net
        )
        ent.cidr_blocks.append({
            "cidr": net.compressed, "ip_version": net.version,
            "prefix_len": net.prefixlen,
            "ip_start_key": format(int(net.network_address), f"0{IP_KEY_WIDTH}x"),
            "ip_end_key": format(int(net.broadcast_address), f"0{IP_KEY_WIDTH}x"),
            "ip_count": net.num_addresses,
            "observed_ip_count": observed,
            "was_scan_target": cidr in corr.scan_cidrs,
            "expanded": cidr in corr.scan_cidrs,
            "source": "mapcidr",
        })

    # Backfill each IP's narrowest containing block. Must happen after the
    # cidr_blocks loop above, not during it — an IP's block isn't known until
    # every block has been considered, and the narrowest (highest prefix_len)
    # match is the useful one when ranges nest.
    blocks_by_version: dict[int, list[dict]] = {}
    for block in ent.cidr_blocks:
        blocks_by_version.setdefault(block["ip_version"], []).append(block)
    for entries in blocks_by_version.values():
        entries.sort(key=lambda b: -b["prefix_len"])
    for entry in ent.ip_addresses:
        addr = ipaddress.ip_address(entry["ip"])
        for block in blocks_by_version.get(entry["ip_version"], []):
            if addr in ipaddress.ip_network(block["cidr"], strict=False):
                entry["cidr"] = block["cidr"]
                break

    # ── Certificates, keyed on the SHA-256 fingerprint ──────────────────────
    by_sha: dict[str, list[dict]] = {}
    for rec in corr.tls:
        sha = ((rec.get("fingerprint_hash") or {}).get("sha256") or "").lower()
        if sha:
            by_sha.setdefault(sha, []).append(rec)

    for sha, recs in by_sha.items():
        first = recs[0]
        cn = (first.get("subject_cn") or "").rstrip(".").lower()
        all_names = {str(n).rstrip(".").lower() for n in (first.get("subject_an") or [])}
        if cn:
            all_names.add(cn)

        names_meta = []
        in_scope_count = foreign_count = new_count = 0
        foreign_domains: set[str] = set()
        for name in sorted(all_names):
            is_wc = name.startswith("*.")
            bare = name[2:] if is_wc else name
            reg = registrable_domain(bare, multi_label_tlds) if not is_address(bare) else ""
            in_scope = reg in our_domains
            discovered_new = name not in known_names
            names_meta.append({
                "cert_sha256": sha, "name": name,
                "name_kind": "cn" if name == cn else "san_dns",
                "is_wildcard": is_wc, "registrable": reg, "in_scope": in_scope,
                "discovered_new": discovered_new,
            })
            if in_scope:
                in_scope_count += 1
            else:
                foreign_count += 1
                if reg:
                    foreign_domains.add(reg)
            if discovered_new:
                new_count += 1
        ent.cert_names.extend(names_meta)

        not_before, not_after = _parse_dt(first.get("not_before")), _parse_dt(first.get("not_after"))
        days_remaining = (not_after - reference_time).days if not_after else None
        age_days = (reference_time - not_before).days if not_before else None
        validity_days = (not_after - not_before).days if (not_after and not_before) else None

        hosts = {r.get("host") for r in recs if r.get("host")}
        ips = {r.get("ip") for r in recs if r.get("ip")}
        wildcard_scope = next((n for n in all_names if n.startswith("*.")), "")

        ent.certificates.append({
            "cert_sha256": sha,
            "subject_cn": cn, "subject_org": ",".join(first.get("subject_org") or []),
            "subject_dn": first.get("subject_dn"),
            "issuer_cn": first.get("issuer_cn"),
            "issuer_org": ",".join(first.get("issuer_org") or []),
            "issuer_dn": first.get("issuer_dn"),
            "serial": first.get("serial"),
            "not_before": first.get("not_before"), "not_after": first.get("not_after"),
            "days_remaining": days_remaining, "age_days": age_days,
            "validity_days": validity_days,
            "expired": any(bool(r.get("expired")) for r in recs),
            "self_signed": any(bool(r.get("self_signed")) for r in recs),
            "mismatched": any(bool(r.get("mismatched")) for r in recs),
            "revoked": any(bool(r.get("revoked")) for r in recs),
            "untrusted": any(bool(r.get("untrusted")) for r in recs),
            "wildcard": any(bool(r.get("wildcard_certificate")) for r in recs),
            "wildcard_scope": wildcard_scope,
            "san_count": len(all_names),
            "in_scope_name_count": in_scope_count,
            "foreign_name_count": foreign_count,
            "foreign_domain_count": len(foreign_domains),
            "new_name_count": new_count,
            "host_count": len(hosts), "ip_count": len(ips),
            "tls_version": first.get("tls_version"), "cipher": first.get("cipher"),
            "cipher_grade": cipher_grade(first.get("cipher") or ""),
            "jarm_hash": first.get("jarm_hash"), "ja3_hash": first.get("ja3_hash"),
            "fingerprint_md5": (first.get("fingerprint_hash") or {}).get("md5"),
            "fingerprint_sha1": (first.get("fingerprint_hash") or {}).get("sha1"),
            "source": "tlsx", "raw": first,
        })

        for r in recs:
            ent.cert_observations.append({
                "cert_sha256": sha, "host": r.get("host") or "",
                "ip": r.get("ip") or "", "port": int(r.get("port") or 443),
                "sni": r.get("sni"),
                "probe_status": bool(r.get("probe_status", True)),
                "error": r.get("error"),
            })

    return ent


def attach(records: list[dict], entities: Entities) -> None:
    """Project the flat, scoring-visible scalars onto each endpoint record.
    Runs AFTER `enrich.enrich()` — `dangling_a_record` needs `serves_content`,
    which enrich.py derives, and there is no other ordering dependency
    between the two passes."""
    ip_by_addr = {e["ip"]: e for e in entities.ip_addresses}
    cert_by_sha = {c["cert_sha256"]: c for c in entities.certificates}
    sans_by_sha: dict[str, list[str]] = {}
    for n in entities.cert_names:
        sans_by_sha.setdefault(n["cert_sha256"], []).append(n["name"])
    # Keyed on (host, port), NOT (host, ip, port): httpx and tlsx each resolve
    # the hostname independently, and with round-robin DNS they routinely
    # land on different addresses for the same host:port pair (confirmed
    # against a real scan — enrich.py's own cross-row pass hits the identical
    # "answering IP is not stable" problem for the same reason). All round-
    # robin addresses behind one hostname normally present the same cert, so
    # matching on the pair that's actually stable is correct, not a
    # loosening — an exact IP match is still preferred when more than one
    # candidate exists.
    obs_by_key: dict[tuple[str, int], list[dict]] = {}
    for o in entities.cert_observations:
        obs_by_key.setdefault((o["host"], o["port"]), []).append(o)

    for rec in records:
        ip = rec.get("host_ip") or ""
        ip_entry = ip_by_addr.get(ip)
        if ip_entry:
            rec["ip_version"] = ip_entry["ip_version"]
            rec["cidr"] = ip_entry.get("cidr") or ""
            rec["ptr_host"] = ip_entry.get("ptr_primary") or ""
            rec["ptr_missing"] = ip_entry.get("ptr_count", 0) == 0
            rec["ptr_mismatch"] = bool(rec["ptr_host"]) and rec["ptr_host"] != rec["host"]
            rec["ip_hostname_count"] = ip_entry.get("hostname_count", 0)
            rec["ip_foreign_name_count"] = ip_entry.get("foreign_name_count", 0)
            rec["ip_foreign_domain_count"] = ip_entry.get("foreign_domain_count", 0)
            rec["in_claimable_range"] = bool(ip_entry.get("in_claimable_range"))
            rec["claimable_provider"] = ip_entry.get("claimable_provider") or ""
            rec["dangling_a_record"] = bool(
                ip_entry.get("in_claimable_range") and not rec.get("serves_content")
            )

        candidates = obs_by_key.get((rec["host"], int(rec["port"])), [])
        obs = next((o for o in candidates if o["ip"] == ip), candidates[0]) if candidates else None
        cert = cert_by_sha.get(obs["cert_sha256"]) if obs else None
        if cert:
            rec["cert_sha256"] = cert["cert_sha256"]
            rec["cert_subject_cn"] = cert.get("subject_cn") or ""
            rec["cert_issuer_org"] = cert.get("issuer_org") or ""
            rec["cert_not_before"] = cert.get("not_before") or ""
            rec["cert_not_after"] = cert.get("not_after") or ""
            rec["cert_days_remaining"] = cert.get("days_remaining")
            rec["cert_age_days"] = cert.get("age_days")
            rec["cert_expired"] = bool(cert.get("expired"))
            rec["cert_self_signed"] = bool(cert.get("self_signed"))
            rec["cert_mismatched"] = bool(cert.get("mismatched"))
            rec["cert_untrusted"] = bool(cert.get("untrusted"))
            rec["cert_revoked"] = bool(cert.get("revoked"))
            rec["cert_wildcard"] = bool(cert.get("wildcard"))
            rec["cert_wildcard_scope"] = cert.get("wildcard_scope") or ""
            rec["cert_san_count"] = cert.get("san_count", 0)
            rec["cert_foreign_domain_count"] = cert.get("foreign_domain_count", 0)
            rec["cert_host_count"] = cert.get("host_count", 0)
            rec["tls_version"] = cert.get("tls_version") or rec.get("tls_version") or ""
            rec["tls_cipher"] = cert.get("cipher") or ""
            rec["tls_cipher_grade"] = cert.get("cipher_grade") or ""
            rec["jarm_hash"] = cert.get("jarm_hash") or rec.get("jarm_hash") or ""
            rec["cert_issuer"] = cert.get("issuer_cn") or rec.get("cert_issuer") or ""
            rec["cert_sans"] = sans_by_sha.get(cert["cert_sha256"], [])
