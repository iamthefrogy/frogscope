"""Rule set loading and validation.

Every rule must carry a `why`, a `remediation`, and (unless it is informational)
an `exec_line`. `rules validate` fails otherwise — a finding a reader cannot act
on is noise, and the only reliable way to keep that true is to refuse to load
rules that lack the text.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from . import predicate

# Fields a rule may reference. Kept explicit so a typo in a rule is caught at
# load time rather than silently never matching.
SCORABLE_FIELDS = {
    # identity
    "host", "port", "scheme", "port_category", "env", "zone", "host_depth",
    "registrable_domain",
    # response
    "response_class", "status_code", "status_class", "title", "title_class",
    "serves_content", "scan_artifact", "cf_alias_port", "waf_blocked",
    "content_type", "content_length", "words", "lines", "response_ms",
    "content_sig", "content_cluster_size", "nonstd_port",
    # redirect and auth
    "final_url", "final_host", "redirect_offsite", "redirect_chain_len",
    "redirects_to_https", "no_tls_redirect", "auth_surface_type", "auth_surface",
    "auth_required", "federated_auth", "remote_access_exposed", "mgmt_surface",
    # edge and hosting
    "cdn_name", "cdn_type", "hosting_provider", "hosting_kind", "edge_provider",
    "edge_kind", "origin_exposed", "no_waf", "waf_protected", "behind_proxy",
    "azure_app_proxy", "origin_health", "cf_error_code", "third_party_dependency",
    "defence_layers", "unprotected", "provider_claimable", "cdn_bypass_candidate",
    "origin_exposure_reason",
    # dns
    "host_ip", "cname_final", "ipv6_enabled", "dns_multi_a", "ip_cluster_size",
    "shared_infra", "concentration_risk",
    # technology
    "webserver", "webserver_family", "webserver_version", "version_disclosure",
    "tech", "tech_names", "tech_count", "tech_flat", "cpe_products",
    "is_wordpress", "wp_plugins", "api_surface", "hsts_present",
    "server_header_inconsistent",
    # lifecycle and takeover, added by the Phase 2 enrichment
    "eol_products", "eol_count", "eol_worst_severity", "eol_years_past",
    "eol_summary", "outdated_components", "outdated_count", "outdated_summary",
    "vuln_families", "vuln_family_count", "vuln_worst_severity", "vuln_summary",
    "takeover_grade", "takeover_provider", "takeover_confidence",
    # business
    "sensitive_keyword", "sensitive_keyword_severity", "is_nonprod_exposed",
    "owner", "business_unit", "criticality",
    # passive product identification, from config/fingerprints.yaml
    "panel_product", "panel_group", "panel_exposure", "panel_confidence",
    "panel_count", "panel_products", "panel_groups",
    "is_default_page", "default_page_product",
    "disclosure_ids", "disclosure_count", "disclosure_worst",
    "fingerprint_count",
    # reserved, inert until httpx is run with richer flags
    "tls_version", "cert_issuer", "cert_not_after", "cert_days_remaining",
    "jarm_hash", "favicon_md5", "asn", "asn_org", "body_preview",
    # v2: cross-asset correlation (dnsx / mapcidr / tlsx), inert until a scan
    # opts into "Correlate assets" — no ASN fields here, see
    # config/cloud_ranges.yaml for why.
    "cidr", "cidr_prefix_len", "ip_version",
    "ptr_host", "ptr_missing", "ptr_mismatch",
    "ip_hostname_count", "ip_foreign_name_count", "ip_foreign_domain_count",
    "in_claimable_range", "claimable_provider", "dangling_a_record",
    "cert_sha256", "cert_subject_cn", "cert_issuer_org", "cert_not_before",
    "cert_age_days", "cert_expired", "cert_self_signed", "cert_mismatched",
    "cert_untrusted", "cert_revoked", "cert_wildcard", "cert_wildcard_scope",
    "cert_san_count", "cert_sans", "cert_foreign_domain_count", "cert_host_count",
    "tls_cipher", "tls_cipher_grade",
}

# What each placeholder stands for, in words. Used when a rule's text is shown
# without a record to fill it — the Methodology view lists definitions, and a bare
# `{vuln_summary}` there looks like a bug rather than a slot.
# What each placeholder stands for, in words. Used when a rule's text is shown
# without a record to fill it — the Methodology view lists definitions, and a bare
# `{vuln_summary}` there reads as a broken template rather than as a slot.
PLACEHOLDER_LABELS = {
    # Chosen to read correctly IN THE SENTENCE, which is why they are not just
    # field names. "Listening on port {port}" needs "N", not "the port", or it
    # renders as "Listening on port the port".
    "cert_days_remaining": "N",        # "expired N days ago"
    "eol_years_past": "N",            # "unsupported for roughly N years"
    "ip_cluster_size": "N",           # "serves N hostnames"
    "port": "N",                      # "listening on port N"
    "status_code": "N",               # "responds N"
    "default_page_product": "The product",
    "env": "non-production",          # "a non-production environment"
    "eol_summary": "an unsupported product",
    "hosting_provider": "a third party",
    "origin_exposure_reason": "The origin is reachable directly",
    "outdated_summary": "the component",
    "panel_product": "The product",
    "sensitive_keyword": "a sensitive word",
    "takeover_provider": "a third-party provider",
    "tls_version": "an old TLS version",
    "vuln_summary": "The product family",
    "webserver": "its exact version",
    # v2 correlation
    "ip_foreign_domain_count": "N",       # "shared with N other domains"
    "ip_hostname_count": "N",
    "cert_san_count": "N",
    "cert_host_count": "N",
    "cert_age_days": "N",
    "cert_subject_cn": "the certificate",
    "cert_issuer_org": "its issuer",
    "cert_wildcard_scope": "a whole domain",
    "claimable_provider": "a cloud provider",
    "cidr": "its address block",
    "ptr_host": "a different name",
    "tls_cipher": "a weak cipher",
    "tls_cipher_grade": "weak",
    "cert_foreign_domain_count": "N",
}


def describe_template(template: str) -> str:
    """A rule's text with placeholders replaced by what they stand for.

    For display only. The scored finding substitutes real observed values.
    """
    import re as _re

    def swap(match):
        return PLACEHOLDER_LABELS.get(match.group(1), match.group(1).replace("_", " "))

    text = _re.sub(r"\{([a-z_]+)\}", swap, template or "").strip()
    # A template often opens with a placeholder, so the label would start the
    # sentence in lower case.
    return text[:1].upper() + text[1:] if text else text


SEVERITIES = ("critical", "high", "medium", "low", "info")
CONFIDENCES = ("confirmed", "probable", "possible")


class RuleError(ValueError):
    pass


@dataclass(frozen=True)
class Rule:
    id: str
    family: str
    bucket: str
    severity: str
    confidence: str
    when: dict
    title: str
    why: str = ""
    exec_line: str = ""
    remediation: str = ""
    points: int | None = None
    map_spec: dict | None = None
    scaled_spec: dict | None = None
    requires_fields: tuple[str, ...] = ()

    def missing_fields(self, record: dict) -> list[str]:
        """Which required fields this record simply does not carry.

        A rule with missing inputs is SKIPPED, never scored. Awarding points for
        absent data is how a scorer ends up ranking everything identically.
        """
        return [
            name for name in self.requires_fields
            if record.get(name) in (None, "", [])
        ]

    def weight_for(self, record: dict) -> int:
        """Resolve this rule's points for a specific record."""
        if self.points is not None:
            return int(self.points)

        if self.map_spec:
            key = str(record.get(self.map_spec["field"]) or "").lower()
            values = {str(k).lower(): v for k, v in (self.map_spec.get("values") or {}).items()}
            return int(values.get(key, 0))

        if self.scaled_spec:
            raw = record.get(self.scaled_spec["field"])
            try:
                amount = float(raw)
            except (TypeError, ValueError):
                return 0
            per = float(self.scaled_spec.get("per", 1))
            ceiling = float(self.scaled_spec.get("max", 999))
            return int(min(ceiling, amount * per))

        return 0

    @property
    def is_positive(self) -> bool:
        return self.family == "positive"

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "family": self.family,
            "bucket": self.bucket,
            "severity": self.severity,
            "confidence": self.confidence,
            "title": self.title,
            "why": self.why,
            "exec_line": self.exec_line,
            "remediation": self.remediation,
            "points": self.points,
            "map": self.map_spec,
            "scaled": self.scaled_spec,
            "requires_fields": list(self.requires_fields),
            "condition": predicate.describe(self.when),
            "condition_tree": self.when,
            "reserved": bool(self.requires_fields),
        }


@dataclass
class Modifier:
    id: str
    when: dict
    factor: float
    reason: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "factor": self.factor, "reason": self.reason,
            "condition": predicate.describe(self.when),
        }


@dataclass
class Exclusion:
    id: str
    when: dict
    reason: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {"id": self.id, "reason": self.reason,
                "condition": predicate.describe(self.when)}


@dataclass
class RuleSet:
    version: int
    max_score: int
    bands: list[dict]
    buckets: dict[str, dict]
    severity_floor: str | None
    overlap_factor: float
    rules: list[Rule]
    modifiers: list[Modifier]
    exclusions: list[Exclusion]
    modifier_floor: float = 0.25
    lifecycle: dict = field(default_factory=dict)
    takeover: dict = field(default_factory=dict)
    rules_hash: str = ""

    def band_for(self, score: int) -> str:
        for band in self.bands:
            if score >= band["min"]:
                return band["name"]
        return self.bands[-1]["name"] if self.bands else "info"

    def band_rank(self, name: str) -> int:
        order = [b["name"] for b in self.bands]
        return order.index(name) if name in order else len(order)

    def bucket_cap(self, bucket: str) -> int:
        return int((self.buckets.get(bucket) or {}).get("cap", self.max_score))

    def by_id(self, rule_id: str) -> Rule | None:
        return next((r for r in self.rules if r.id == rule_id), None)

    def as_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "rules_hash": self.rules_hash,
            "max_score": self.max_score,
            "bands": self.bands,
            "buckets": self.buckets,
            "severity_floor": self.severity_floor,
            "overlap_factor": self.overlap_factor,
            "modifier_floor": self.modifier_floor,
            "rules": [r.as_dict() for r in self.rules],
            "modifiers": [m.as_dict() for m in self.modifiers],
            "exclusions": [e.as_dict() for e in self.exclusions],
        }


def _load_yaml(path: Path) -> dict:
    if not path.exists():
        raise RuleError(f"missing config file: {path}")
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise RuleError(f"{path} is not valid YAML: {exc}") from exc


def load_ruleset(config_dir: Path) -> RuleSet:
    rules_path = config_dir / "rules.yaml"
    raw = _load_yaml(rules_path)
    lifecycle = _load_yaml(config_dir / "lifecycle.yaml")
    takeover = _load_yaml(config_dir / "takeover.yaml")

    digest = hashlib.sha256()
    for path in (rules_path, config_dir / "lifecycle.yaml", config_dir / "takeover.yaml"):
        digest.update(path.read_bytes())

    scale = raw.get("scale") or {}
    bands = sorted(scale.get("bands") or [], key=lambda b: -int(b["min"]))

    rules: list[Rule] = []
    for entry in raw.get("rules") or []:
        rules.append(Rule(
            id=entry["id"],
            family=entry.get("family", "other"),
            bucket=entry.get("bucket", "exposure"),
            severity=entry.get("severity", "info"),
            confidence=entry.get("confidence", "confirmed"),
            when=entry.get("when") or {},
            title=entry.get("title", entry["id"]),
            why=(entry.get("why") or "").strip(),
            exec_line=(entry.get("exec_line") or "").strip(),
            remediation=(entry.get("remediation") or "").strip(),
            points=entry.get("points"),
            map_spec=entry.get("map"),
            scaled_spec=entry.get("scaled"),
            requires_fields=tuple(entry.get("requires_fields") or ()),
        ))

    ruleset = RuleSet(
        version=int(raw.get("version", 1)),
        max_score=int(scale.get("max", 100)),
        bands=bands,
        buckets=raw.get("buckets") or {},
        severity_floor=raw.get("severity_floor"),
        overlap_factor=float((raw.get("families") or {}).get("overlap_factor", 0.3)),
        modifier_floor=float(raw.get("modifier_floor", 0.25)),
        rules=rules,
        modifiers=[
            Modifier(id=m["id"], when=m.get("when") or {},
                     factor=float(m.get("factor", 1.0)),
                     reason=(m.get("reason") or "").strip())
            for m in raw.get("modifiers") or []
        ],
        exclusions=[
            Exclusion(id=e["id"], when=e.get("when") or {},
                      reason=(e.get("reason") or "").strip())
            for e in raw.get("exclusions") or []
        ],
        lifecycle=lifecycle,
        takeover=takeover,
        rules_hash=digest.hexdigest()[:16],
    )

    problems = validate_ruleset(ruleset)
    if problems:
        raise RuleError("rules are invalid:\n  - " + "\n  - ".join(problems))
    return ruleset


def validate_ruleset(ruleset: RuleSet) -> list[str]:
    problems: list[str] = []

    if not ruleset.rules:
        problems.append("no rules defined")
    if not ruleset.bands:
        problems.append("no severity bands defined")
    if not ruleset.buckets:
        problems.append("no buckets defined")

    seen: set[str] = set()
    for rule in ruleset.rules:
        prefix = f"rule {rule.id}"
        if rule.id in seen:
            problems.append(f"{prefix}: duplicate id")
        seen.add(rule.id)

        if rule.bucket not in ruleset.buckets:
            problems.append(f"{prefix}: unknown bucket {rule.bucket!r}")
        if rule.severity not in SEVERITIES:
            problems.append(f"{prefix}: unknown severity {rule.severity!r}")
        if rule.confidence not in CONFIDENCES:
            problems.append(f"{prefix}: unknown confidence {rule.confidence!r}")

        scorers = [rule.points is not None, rule.map_spec is not None,
                   rule.scaled_spec is not None]
        if sum(scorers) != 1:
            problems.append(
                f"{prefix}: needs exactly one of points, map, or scaled")
        if rule.map_spec and "field" not in rule.map_spec:
            problems.append(f"{prefix}: map needs a `field`")
        if rule.scaled_spec and "field" not in rule.scaled_spec:
            problems.append(f"{prefix}: scaled needs a `field`")

        problems.extend(
            f"{prefix}: {issue}"
            for issue in predicate.validate(rule.when, SCORABLE_FIELDS)
        )

        for name in rule.requires_fields:
            if name not in SCORABLE_FIELDS:
                problems.append(f"{prefix}: requires unknown field {name!r}")

        # A finding nobody can act on is noise. Enforce the text rather than
        # trusting authors to remember it.
        if not rule.is_positive and rule.severity != "info":
            if not rule.why:
                problems.append(f"{prefix}: missing `why`")
            if not rule.remediation:
                problems.append(f"{prefix}: missing `remediation`")
            if not rule.exec_line:
                problems.append(f"{prefix}: missing `exec_line`")

    for modifier in ruleset.modifiers:
        problems.extend(
            f"modifier {modifier.id}: {issue}"
            for issue in predicate.validate(modifier.when, SCORABLE_FIELDS)
        )
        if not 0 < modifier.factor <= 4:
            problems.append(
                f"modifier {modifier.id}: implausible factor {modifier.factor}")
        if not modifier.reason:
            problems.append(
                f"modifier {modifier.id}: missing `reason` — a modifier that "
                f"silently halves a score is indistinguishable from a bug")

    for exclusion in ruleset.exclusions:
        problems.extend(
            f"exclusion {exclusion.id}: {issue}"
            for issue in predicate.validate(exclusion.when, SCORABLE_FIELDS)
        )

    band_names = [b["name"] for b in ruleset.bands]
    if ruleset.severity_floor and ruleset.severity_floor not in band_names:
        problems.append(
            f"severity_floor {ruleset.severity_floor!r} is not one of {band_names}")

    return problems


def rules_fingerprint(ruleset: RuleSet) -> str:
    """Stable hash of the scoring behaviour, recorded on every run.

    If this changes between runs, a score delta may be a re-scoring rather than a
    real-world change — and the UI needs to be able to say so.
    """
    payload = json.dumps(
        {
            "version": ruleset.version,
            "bands": ruleset.bands,
            "buckets": {k: v.get("cap") for k, v in ruleset.buckets.items()},
            "overlap": ruleset.overlap_factor,
            "modifier_floor": ruleset.modifier_floor,
            "floor": ruleset.severity_floor,
            "rules": sorted(
                (r.id, r.bucket, r.points, json.dumps(r.map_spec, sort_keys=True),
                 json.dumps(r.scaled_spec, sort_keys=True), r.severity)
                for r in ruleset.rules
            ),
            "modifiers": sorted((m.id, m.factor) for m in ruleset.modifiers),
        },
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode()).hexdigest()[:16]
