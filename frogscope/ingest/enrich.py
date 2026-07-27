"""Derive every analytical field from the normalised records.

Two passes, because some fields cannot be computed from a single row:

* **Row pass** — everything derivable from one endpoint.
* **Cross-row pass** — shared-IP blast radius, content clusters, and
  ``cdn_bypass_candidate`` (a host whose :443 sits behind a WAF while another
  port on the same host is directly exposed, meaning the WAF is bypassable).
  That last one is a real finding that nothing in the raw CSV surfaces.
"""

from __future__ import annotations

from collections import Counter, defaultdict

from ..config import Config
from . import classify, fingerprint
from .normalize import content_signature, is_address


def enrich(records: list[dict], cfg: Config, *,
          ptr_by_ip: dict[str, str] | None = None) -> list[dict]:
    catalogue = fingerprint.load_catalogue(cfg.config_dir)
    ptr_by_ip = ptr_by_ip or {}
    for rec in records:
        _enrich_row(rec, cfg, ptr_by_ip)
        # Product identification is separate from scoring on purpose: this says
        # WHAT is reachable, and rules.yaml decides whether it matters.
        rec.update(fingerprint.identify(rec, catalogue))
    _enrich_cross_row(records, cfg)
    return records


def _enrich_row(rec: dict, cfg: Config, ptr_by_ip: dict[str, str]) -> None:
    # httpx reports the answering address in its `host` column, which the loader
    # keeps as `answered_from` because `host` is the hostname here. Where no
    # separate host_ip column existed, that IS the resolved address.
    if not rec.get("host_ip") and rec.get("answered_from"):
        rec["host_ip"] = rec["answered_from"]

    host = rec["host"]
    port = int(rec["port"])
    scheme = rec.get("scheme") or ""
    status = rec.get("status_code")

    # A bare-IP host has nothing keyword-classifiable in it ("203" matches
    # nothing) — fall back to its PTR name where one was found, so an address
    # that reverse-resolves to e.g. prod-db-01.internal.corp.com still gets
    # classified. Empty when no PTR name exists, same as classifying the
    # digits themselves would have produced.
    classify_host = ptr_by_ip.get(rec.get("host_ip") or host, "") if is_address(host) else host

    # ── identity ────────────────────────────────────────────────────────────
    rec["env"], rec["env_source"] = classify.env_of(classify_host, cfg)
    rec["zone"], rec["registrable_domain"] = classify.zone_and_domain(host, cfg)
    rec["host_depth"] = len(host.split("."))
    rec["port_category"] = classify.port_category(port, cfg)

    # ── redirect, before response_class (auth detection depends on it) ───────
    rec["final_host"] = classify.final_host_of(rec.get("final_url") or "")
    rec["redirect_chain_len"] = len(rec.get("redirect_chain") or [])
    rec["redirect_offsite"] = bool(rec["final_host"]) and rec["final_host"] != host
    rec["redirects_to_https"] = (
        scheme == "http" and (rec.get("final_url") or "").startswith("https://")
    )

    # ── titles ──────────────────────────────────────────────────────────────
    tclass, tlabel, artifact = classify.title_class(rec.get("title") or "", cfg)
    rec["title_class"] = tclass
    rec["title_class_label"] = tlabel

    # ── auth ────────────────────────────────────────────────────────────────
    auth_type, federated = classify.auth_surface(rec, cfg, tclass)
    rec["auth_surface_type"] = auth_type
    rec["federated_auth"] = federated
    rec["remote_access_exposed"] = (
        auth_type in cfg.remote_access_auth_types
        or bool(set(rec.get("cpe_products") or []) & cfg.remote_access_cpe)
    )
    rec["mgmt_surface"] = tclass == "mgmt_console"

    # ── response class (depends on auth_surface_type) ────────────────────────
    rclass = classify.response_class(rec, cfg, tclass, artifact)
    rec["response_class"] = rclass
    rec["scan_artifact"] = rclass == "scan_artifact"
    rec["waf_blocked"] = rclass in ("waf_blocked", "waf_challenge")
    rec["serves_content"] = rclass in ("live_content", "auth_required")
    rec["status_class"] = f"{status // 100}xx" if status else "none"
    rec["content_sig"] = content_signature(rec)

    cdn_name = (rec.get("cdn_name") or "").lower()
    rec["cf_alias_port"] = (cdn_name in cfg.alias_port_providers
                            and port in cfg.cf_alias_ports)
    # Paired with cf_alias_port everywhere it is used: on a Cloudflare-fronted
    # host most "non-standard" ports are aliases of :443, not extra services.
    rec["nonstd_port"] = port not in cfg.standard_ports

    # ── edge and hosting ────────────────────────────────────────────────────
    provider, kind, claimable = classify.hosting_provider(rec, cfg)
    rec["hosting_provider"] = provider
    rec["hosting_kind"] = kind
    rec["provider_claimable"] = claimable
    rec["cname_final"] = (rec.get("cname") or [""])[-1] if rec.get("cname") else ""

    # The origin provider and the edge provider are different questions. A chain
    # through Entra App Proxy that terminates at Traffic Manager is both "an
    # internal app published externally" and "fronted by Traffic Manager".
    edge_name, edge_kind = classify.edge_provider(rec, cfg)
    rec["edge_provider"] = edge_name
    rec["edge_kind"] = edge_kind
    rec["chain_providers"] = classify.chain_providers(rec, cfg)

    # Three different questions, deliberately kept apart. Collapsing them into
    # one "exposed" flag is how a dashboard ends up telling an executive that a
    # pre-authenticated Entra App Proxy endpoint is an unprotected origin.
    #
    #   waf_protected  — is there a WAF or CDN inspecting this traffic?
    #   behind_proxy   — is there ANY managed intermediary, or does the internet
    #                    reach a server we run directly?
    #   origin_exposed — serving content with no intermediary at all.
    rec["waf_protected"] = (
        (rec.get("cdn_type") or "").lower() == "waf"
        or kind in cfg.cdn_provider_kinds
        or edge_kind in cfg.cdn_provider_kinds
    )
    behind_proxy = bool(rec.get("cdn")) or bool(kind) or bool(edge_kind)
    rec["behind_proxy"] = behind_proxy
    rec["origin_exposed"] = bool(rec["serves_content"]) and not behind_proxy
    rec["no_waf"] = bool(rec["serves_content"]) and not rec["waf_protected"]

    if behind_proxy:
        rec["origin_exposure_reason"] = ""
    else:
        rec["origin_exposure_reason"] = (
            "no CDN flag set, and no CNAME target matches a known provider — "
            "the internet appears to reach this server directly"
        )
    rec["azure_app_proxy"] = "app_proxy" in (kind, edge_kind) or any(
        "msappproxy" in c or "appproxy.msidentity" in c
        for c in (rec.get("cname") or [])
    )
    rec["third_party_dependency"] = (
        "" if not kind else ("edge" if kind in cfg.cdn_provider_kinds
                             else ("saas" if kind in ("saas", "paas") else "none"))
    )
    rec["origin_health"], rec["cf_error_code"] = classify.origin_health(rec, cfg)

    # ── encryption posture ──────────────────────────────────────────────────
    rec["no_tls_redirect"] = (
        scheme == "http"
        and rec["serves_content"]
        and not rec["redirects_to_https"]
        and not rec["scan_artifact"]
    )
    rec["hsts_present"] = any(
        str(t).upper() == "HSTS" for t in (rec.get("tech") or [])
    )

    layers = 0
    if rec["waf_protected"] or kind == "app_proxy":
        # App Proxy pre-authenticates, so it counts as a protective layer even
        # though it is not a WAF.
        layers += 1
    if auth_type != "none" or status == 401:
        layers += 1
    if scheme == "https":
        layers += 1
    rec["defence_layers"] = layers
    rec["unprotected"] = bool(rec["serves_content"]) and layers == 0

    # ── dns ─────────────────────────────────────────────────────────────────
    rec["ipv6_enabled"] = bool(rec.get("aaaa"))
    rec["dns_multi_a"] = len(rec.get("a") or []) > 1

    # ── technology ──────────────────────────────────────────────────────────
    family, version, disclosed = classify.split_webserver(rec.get("webserver") or "")
    rec["webserver_family"] = family
    rec["webserver_version"] = version
    rec["version_disclosure"] = disclosed

    tech_names, tech_versions = classify.split_tech_versions(rec.get("tech") or [])
    rec["tech_names"] = tech_names
    rec["tech_versions"] = tech_versions
    rec["tech_count"] = len(rec.get("tech") or [])
    rec["tech_flat"] = " ".join(str(t).lower() for t in rec.get("tech") or [])
    rec["is_wordpress"] = (
        bool(rec.get("wp_plugins"))
        or any("wordpress" in str(t).lower() for t in rec.get("tech") or [])
    )
    rec["api_surface"] = (
        (rec.get("content_type") or "") in
        ("application/json", "application/xml", "text/xml")
        and str(rec.get("status_class")) == "2xx"
    )

    # ── ownership (empty unless config/ownership.yaml is filled in) ─────────
    owner = cfg.owner_for(host)
    rec["owner"] = owner["owner"]
    rec["business_unit"] = owner["business_unit"]
    rec["criticality"] = owner["criticality"]

    # ── sensitivity hint (feeds Phase 2 scoring) ────────────────────────────
    sev, token = classify.sensitivity_keyword(classify_host, cfg)
    rec["sensitive_keyword_severity"] = sev
    rec["sensitive_keyword"] = token
    rec["is_nonprod_exposed"] = (
        rec["env"] in cfg.nonprod_envs and bool(rec["serves_content"])
    )


def _addresses(rec: dict) -> set[str]:
    """Every address this name resolves to, plus the one that answered."""
    out = {str(ip) for ip in (rec.get("a") or []) if ip}
    out |= {str(ip) for ip in (rec.get("aaaa") or []) if ip}
    if rec.get("host_ip"):
        out.add(str(rec["host_ip"]))
    return out


def _enrich_cross_row(records: list[dict], cfg: Config) -> None:
    # Shared-IP blast radius.
    #
    # Built from the whole A-record set, not the single address that happened to
    # answer. With round-robin DNS the answering IP rotates between probes, and
    # two addresses in the same rotation can front different numbers of hosts —
    # so keying on `host_ip` alone makes the cluster size, and every finding
    # derived from it, flip between runs for no real-world reason. That is noise
    # that looks exactly like signal in a weekly diff.
    hosts_per_ip: dict[str, set[str]] = defaultdict(set)
    for rec in records:
        for ip in _addresses(rec):
            hosts_per_ip[ip].add(rec["host"])

    # Template-identical endpoints, so hundreds of copies of one app collapse
    # to a single reviewable row.
    sig_counts = Counter(rec["content_sig"] for rec in records)

    # A host is WAF-fronted somewhere and directly exposed somewhere else.
    waf_hosts: set[str] = set()
    exposed_hosts: set[str] = set()
    for rec in records:
        if rec.get("waf_blocked") or (rec.get("cdn_type") or "") == "waf":
            waf_hosts.add(rec["host"])
        if rec.get("origin_exposed"):
            exposed_hosts.add(rec["host"])
    bypassable = waf_hosts & exposed_hosts

    # Same host serving different web servers on different ports — a shadow
    # service or a different backend.
    servers_per_host: dict[str, set[str]] = defaultdict(set)
    for rec in records:
        if rec.get("webserver"):
            servers_per_host[rec["host"]].add(rec["webserver"])

    for rec in records:
        # Max across the record set: the blast radius of the busiest address this
        # name resolves to, which is stable however the rotation answers.
        cluster = max(
            (len(hosts_per_ip.get(ip, ())) for ip in _addresses(rec)),
            default=0,
        )
        rec["ip_cluster_size"] = cluster
        rec["shared_infra"] = cluster >= 5
        rec["concentration_risk"] = cluster >= 50
        rec["content_cluster_size"] = sig_counts[rec["content_sig"]]
        rec["cdn_bypass_candidate"] = rec["host"] in bypassable
        rec["server_header_inconsistent"] = len(servers_per_host.get(rec["host"], ())) > 1
