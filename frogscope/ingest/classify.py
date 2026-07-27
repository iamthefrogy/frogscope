"""Per-field classifiers. All rules come from config, never hardcoded here."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit

from ..config import Config
from .normalize import registrable_domain, zone_of

_LABEL_SPLIT = re.compile(r"[.\-_]")

# Statuses that mean "something is actually listening and serving", as opposed
# to a rejection, a not-found, or a scan artefact.
SERVING_STATUSES = {200, 201, 202, 203, 204, 206, 301, 302, 303, 307, 308}


def title_class(title: str, cfg: Config) -> tuple[str, str, bool]:
    """Return (class, label, is_artifact). Ordered — first match wins."""
    text = (title or "").strip()
    if not text:
        return "blank_title", "No title", False
    for name, label, pattern, artifact in cfg.title_patterns:
        if pattern.search(text):
            return name, label, artifact
    return "other", "Other", False


def env_of(host: str, cfg: Config) -> tuple[str, str]:
    """Return (env, evidence_token).

    Matched against whole hostname labels. Substring matching is wrong: "data"
    contains "ta", "latest" contains "test". Where several environments match,
    the one latest in config precedence wins, so a host called
    'uat-dev-thing' reads as the more non-production of the two.
    """
    best_env: str | None = None
    best_token = ""
    best_rank = -1

    for label in host.split("."):
        for token in _LABEL_SPLIT.split(label):
            if not token:
                continue
            env = cfg.env_lookup.get(token.lower())
            if env is None:
                continue
            rank = cfg.env_precedence.get(env, 0)
            if rank > best_rank or (rank == best_rank and len(token) > len(best_token)):
                best_env, best_token, best_rank = env, token, rank

    if best_env is None:
        return cfg.env_default, ""
    return best_env, best_token


def zone_and_domain(host: str, cfg: Config) -> tuple[str, str]:
    root = registrable_domain(host, cfg.multi_label_tlds)
    override = (cfg.classify.get("zone_overrides") or {}).get(host)
    zone = override or zone_of(host, root)
    return zone, root


# How informative each provider kind is about *what actually hosts the app*.
# Higher wins. A chain ending at Traffic Manager or Cloudflare only tells you
# the edge; a chain passing through App Proxy or WP Engine tells you the origin,
# which is the more actionable fact — so it must not be discarded just because
# it sits earlier in the chain.
_KIND_SPECIFICITY = {
    "app_proxy": 60,
    "storage": 55,
    "paas": 50,
    "saas": 45,
    "iaas": 40,
    "identity": 30,
    "cdn": 20,
    "waf": 20,
    "dns": 10,
    "": 0,
}


def _chain_matches(rec: dict, cfg: Config) -> list[tuple[int, dict]]:
    """Every provider match along the CNAME chain, with its chain position."""
    matches: list[tuple[int, dict]] = []
    for position, cname in enumerate(rec.get("cname") or []):
        target = str(cname).rstrip(".").lower()
        for entry in cfg.cname_providers:      # already longest-suffix-first
            suffix = entry["suffix"]
            if target == suffix or target.endswith("." + suffix):
                matches.append((position, entry))
                break
    return matches


def hosting_provider(rec: dict, cfg: Config) -> tuple[str, str, bool]:
    """Resolve the *origin* provider — the most specific match in the chain.

    Returns (provider, kind, claimable).
    """
    matches = _chain_matches(rec, cfg)
    if matches:
        # Most specific kind wins; ties broken by earliest chain position, since
        # the front of the chain is closest to the origin.
        position, entry = min(
            matches,
            key=lambda m: (-_KIND_SPECIFICITY.get(m[1].get("kind", ""), 0), m[0]),
        )
        return entry["provider"], entry.get("kind", ""), bool(entry.get("claimable"))

    cdn_name = (rec.get("cdn_name") or "").strip()
    if cdn_name:
        kind = (rec.get("cdn_type") or "").strip() or "cdn"
        return cdn_name.title() if cdn_name.islower() else cdn_name, kind, False

    return "", "", False


def edge_provider(rec: dict, cfg: Config) -> tuple[str, str]:
    """Resolve the *outermost* provider — what the internet actually talks to."""
    matches = _chain_matches(rec, cfg)
    if matches:
        _position, entry = max(matches, key=lambda m: m[0])
        return entry["provider"], entry.get("kind", "")

    cdn_name = (rec.get("cdn_name") or "").strip()
    if cdn_name:
        return (cdn_name.title() if cdn_name.islower() else cdn_name,
                (rec.get("cdn_type") or "").strip() or "cdn")
    return "", ""


def chain_providers(rec: dict, cfg: Config) -> list[str]:
    """Every distinct provider the traffic passes through — the supply chain."""
    seen: list[str] = []
    for _position, entry in _chain_matches(rec, cfg):
        if entry["provider"] not in seen:
            seen.append(entry["provider"])
    return seen


def auth_surface(rec: dict, cfg: Config, tclass: str) -> tuple[str, bool]:
    """Return (auth_surface_type, federated).

    Federation is a *good* property — the risk is a login surface that handles
    credentials locally. So both facts are recorded rather than collapsed.
    """
    final_host = rec.get("final_host") or ""
    federated = any(idp in final_host for idp in cfg.idp_hosts)

    haystack = " ".join(
        str(x) for x in (
            rec.get("host") or "",
            rec.get("title") or "",
            final_host,
            rec.get("final_url") or "",
            " ".join(rec.get("cpe_products") or []),
            " ".join(rec.get("tech") or []),
        )
    )
    for auth_type, pattern in cfg.auth_type_patterns:
        if pattern.search(haystack):
            return auth_type, federated

    if tclass in ("m365_login", "adfs_login", "generic_login"):
        return "generic_login", federated
    if federated:
        return "m365_login" if "microsoftonline" in final_host else "generic_login", True
    return "none", False


def response_class(rec: dict, cfg: Config, tclass: str, artifact: bool) -> str:
    """The single most useful derived field.

    An ordered ladder, first match wins. This is what separates real content
    from WAF blocks, scan artefacts, broken origins, and auth walls — without
    it, a naive "is it alive" count treats all of them as live surface.
    """
    status = rec.get("status_code")
    port = rec.get("port")
    scheme = rec.get("scheme")
    cdn_name = (rec.get("cdn_name") or "").lower()

    # httpx probed a TLS-only port over cleartext; the 400 is the server being
    # correct, and it is a large fraction of a default-flag scan.
    if artifact or (scheme == "http" and status == 400 and port in cfg.tls_only_ports):
        return "scan_artifact"

    if status is None:
        return "dead"

    if tclass == "cf_challenge":
        return "waf_challenge"
    if tclass == "cf_block" or (status == 403
                               and cdn_name in cfg.origin_error_providers):
        return "waf_blocked"

    cf = cfg.cf_error_codes.get(int(status))
    if cf and cdn_name in cfg.origin_error_providers:
        return {
            "dns_missing": "origin_unreachable",
            "tls_broken": "origin_tls_failure",
            "unreachable": "origin_unreachable",
        }.get(cf.get("health", ""), "server_error")

    if status == 401:
        return "auth_required"
    if rec.get("auth_surface_type", "none") != "none" and status in (200, 302, 303):
        return "auth_required"

    if status >= 500:
        return "server_error"
    if status == 404 or tclass in ("azure_404", "notfound"):
        return "not_found"
    if status == 403:
        return "forbidden"
    if status >= 400:
        return "client_error"

    if 300 <= status < 400 and not (rec.get("content_length") or 0):
        return "redirect_only"

    if tclass == "parked" or (
        status == 200
        and not (rec.get("title") or "").strip()
        and (rec.get("content_length") or 0) < 256
    ):
        return "parked"

    if status in SERVING_STATUSES:
        return "live_content"
    return "other"


def origin_health(rec: dict, cfg: Config) -> tuple[str, int | None]:
    """Decode Cloudflare 5xx codes.

    530 means error 1016 — the origin DNS record does not resolve, which is a
    takeover signal. 525/526 mean the origin is reachable but its TLS is broken,
    which is an availability bug. Conflating the two produces false takeover
    alerts, so they are separated here.
    """
    status = rec.get("status_code")
    if status is None:
        return "unknown", None
    entry = cfg.cf_error_codes.get(int(status))
    if not entry:
        return "ok", None
    if (rec.get("cdn_name") or "").lower() not in cfg.origin_error_providers:
        return "ok", None
    return entry.get("health", "unknown"), entry.get("code")


def port_category(port: int, cfg: Config) -> str:
    return cfg.port_category.get(int(port), "other")


def split_webserver(webserver: str) -> tuple[str, str, bool]:
    """'Microsoft-IIS/10.0' -> ('Microsoft-IIS', '10.0', True)."""
    text = (webserver or "").strip()
    if not text:
        return "", "", False
    head, _, tail = text.partition("/")
    version = tail.split()[0].strip() if tail else ""
    has_version = bool(version and any(c.isdigit() for c in version))
    return head.strip(), version if has_version else "", has_version


def split_tech_versions(tech: list[str]) -> tuple[list[str], dict[str, str]]:
    """'IIS:10.0' -> names ['IIS'], versions {'IIS': '10.0'}."""
    names: list[str] = []
    versions: dict[str, str] = {}
    for item in tech or []:
        text = str(item).strip()
        if not text:
            continue
        name, sep, version = text.rpartition(":")
        if sep and version and version[0].isdigit():
            names.append(name)
            versions[name] = version
        else:
            names.append(text)
    return names, versions


def final_host_of(final_url: str) -> str:
    if not final_url:
        return ""
    try:
        return (urlsplit(final_url).hostname or "").lower()
    except ValueError:
        return ""


def sensitivity_keyword(host: str, cfg: Config) -> tuple[str, str]:
    """Return (severity, matched_token) for sensitive hostname tokens."""
    tokens = {t.lower() for label in host.split(".") for t in _LABEL_SPLIT.split(label) if t}
    keywords: dict[str, Any] = cfg.classify.get("sensitive_keywords") or {}
    for severity in ("high", "medium", "low"):
        for kw in keywords.get(severity) or []:
            if kw.lower() in tokens:
                return severity, kw
    return "", ""
