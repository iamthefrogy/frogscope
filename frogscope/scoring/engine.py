"""Scoring engine.

Keeps the bucket-and-cap shape of frogy_web/scoring/engine.py, which is a good
model — an executive understands "reachable / neglected / valuable". Four
deliberate departures, each fixing something in the original:

1. **A rule with missing inputs is skipped, not penalised.** The original awards
   +25 hygiene against a cap of exactly 25 for absent TLS, DMARC, SPF, DKIM, and
   DNSSEC data. Fed an httpx-only CSV, every endpoint would max out its entire
   hygiene bucket on data that was never collected, and the ranking would be
   noise. Skipped rules are reported so the gap is visible.

2. **Capping is deterministic.** The original applies caps in source order, so
   which signals get truncated depends on where they happen to sit in the file.
   Here contributions are sorted by (-points, rule_id) first.

3. **Every contribution is kept**, not the top five. The drawer shows the whole
   trace, so "why 72?" has an exact answer.

4. **Contributions carry the observed values** as evidence, so the explanation is
   "because webserver == 'Microsoft-IIS/10.0'", not a bare sentence.
"""

from __future__ import annotations

import math
import re
from dataclasses import asdict, dataclass, field
from typing import Any

from . import predicate
from .rules import Rule, RuleSet

_PLACEHOLDER = re.compile(r"\{([a-z_][a-z0-9_]*)\}", re.I)


@dataclass
class Contribution:
    rule_id: str
    family: str
    bucket: str
    severity: str
    confidence: str
    title: str
    points_raw: int
    points_applied: int
    capped: bool
    family_discounted: bool
    why: str
    remediation: str
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class AppliedModifier:
    id: str
    factor: float
    reason: str


@dataclass
class ScoreResult:
    score: int
    band: str
    buckets: dict[str, int]
    raw_score: int
    contributions: list[Contribution]
    modifiers: list[AppliedModifier]
    skipped: list[dict[str, Any]]
    excluded: bool = False
    excluded_by: str = ""
    excluded_reason: str = ""
    floored_from: str = ""
    worst_severity: str = ""
    mitigated: bool = False
    confidence: str = "confirmed"
    coverage: float = 1.0

    def as_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "band": self.band,
            "buckets": self.buckets,
            "raw_score": self.raw_score,
            "contributions": [asdict(c) for c in self.contributions],
            "modifiers": [asdict(m) for m in self.modifiers],
            "skipped": self.skipped,
            "excluded": self.excluded,
            "excluded_by": self.excluded_by,
            "excluded_reason": self.excluded_reason,
            "floored_from": self.floored_from,
            "worst_severity": self.worst_severity,
            "mitigated": self.mitigated,
            "confidence": self.confidence,
            "coverage": self.coverage,
        }

    @property
    def findings(self) -> list[Contribution]:
        """Contributions worth raising as findings, worst first."""
        return [
            c for c in self.contributions
            if c.family != "positive" and c.severity != "info"
        ]

    @property
    def positives(self) -> list[Contribution]:
        return [c for c in self.contributions if c.family == "positive"]


# Data families a scoring decision can draw on. Used to report how much of the
# picture this scan actually covered, so a low score on thin data is not mistaken
# for a clean bill of health.
COVERAGE_FAMILIES = {
    "response": ("status_code",),
    "dns": ("host_ip",),
    "edge": ("cdn_name", "hosting_provider"),
    "technology": ("tech", "webserver"),
    "cpe": ("cpe_products",),
    "redirect": ("final_url",),
    # v2: "certificate"/"network" were reserved-but-permanently-empty before
    # dnsx/tlsx correlation existed (nothing ever populated `cert_not_after`
    # or `asn`). Widened to the fields v2 actually fills, rather than adding
    # two MORE families — that would change the denominator in
    # `coverage_of()` and silently flip every historical run's confidence
    # label. `asn` itself stays out: this release has no ASN data (see
    # config/cloud_ranges.yaml for why), so `cidr`/`ptr_host` are the
    # network-layer facts that are actually fillable now.
    "certificate": ("cert_not_after", "cert_sha256"),
    "network": ("cidr", "ptr_host"),
}


def _render(template: str, record: dict) -> str:
    """Fill {placeholders} from the record.

    An unfillable placeholder is REMOVED, not left in place. Showing a reader
    `{vuln_summary}` looks like a broken template and costs credibility on every
    other number on the page — and a rule can legitimately fire while an optional
    detail field is empty.

    Removing one can leave dangling punctuation ("`{x}`. The rest…" becomes
    ". The rest…"), so the result is tidied afterwards.
    """
    def swap(match: re.Match) -> str:
        value = record.get(match.group(1))
        if value is None or value == "":
            return ""
        if isinstance(value, (list, tuple)):
            return ", ".join(str(v) for v in value)
        if isinstance(value, float):
            return f"{value:.1f}".rstrip("0").rstrip(".")
        return str(value)

    text = _PLACEHOLDER.sub(swap, template or "")
    # Tidy what an empty substitution leaves behind: a leading separator, a
    # doubled space, or a space before punctuation.
    text = re.sub(r"^[\s.,;:—-]+", "", text)
    text = re.sub(r"\s+([.,;:])", r"\1", text)
    text = re.sub(r"\s{2,}", " ", text)
    # A parenthetical whose only content was the placeholder: "( years)".
    text = re.sub(r"\(\s*[a-z%]*\s*\)", "", text)
    # An empty first sentence leaves ". Next sentence" mid-string.
    text = re.sub(r"(?<=[.!?])\s*\.\s*", " ", text)
    result = text.strip()
    # Capitalise if removing the placeholder cost us the opening word.
    return result[:1].upper() + result[1:] if result else result


def _evidence_for(rule: Rule, record: dict) -> dict[str, Any]:
    """The observed values that made this rule fire."""
    names: set[str] = set()

    def walk(node: Any) -> None:
        if not isinstance(node, dict):
            return
        for key in ("all", "any"):
            if key in node:
                for child in node[key]:
                    walk(child)
                return
        if "not" in node:
            walk(node["not"])
            return
        if "field" in node:
            names.add(node["field"])

    walk(rule.when)
    if rule.map_spec:
        names.add(rule.map_spec["field"])
    if rule.scaled_spec:
        names.add(rule.scaled_spec["field"])

    evidence: dict[str, Any] = {}
    for name in sorted(names):
        value = record.get(name)
        if value in (None, "", []):
            continue
        evidence[name] = value[:6] if isinstance(value, list) else value
    return evidence


SEVERITY_RANK = ("critical", "high", "medium", "low", "info")


def _worst_severity(contributions: list[Contribution]) -> str:
    """The most severe finding on this endpoint.

    Reported separately from the band, because they answer different questions:
    the band is how risky this endpoint is overall, this is how bad its worst
    single issue is. A WAF-protected endpoint running end-of-life software has a
    modest band and a critical worst-severity, and both facts are true.
    """
    present = {c.severity for c in contributions if c.family != "positive"}
    for level in SEVERITY_RANK:
        if level in present:
            return level
    return ""


def coverage_of(record: dict) -> tuple[float, list[str]]:
    present = 0
    absent: list[str] = []
    for family, fields in COVERAGE_FAMILIES.items():
        if any(record.get(f) not in (None, "", []) for f in fields):
            present += 1
        else:
            absent.append(family)
    return present / len(COVERAGE_FAMILIES), absent


def score_record(record: dict, ruleset: RuleSet) -> ScoreResult:
    # ── Exclusions ──────────────────────────────────────────────────────────
    for exclusion in ruleset.exclusions:
        if predicate.evaluate(exclusion.when, record):
            return ScoreResult(
                score=0, band="info", buckets={}, raw_score=0,
                contributions=[], modifiers=[], skipped=[],
                excluded=True, excluded_by=exclusion.id,
                excluded_reason=exclusion.reason,
            )

    # ── Match, skipping anything whose inputs were never collected ──────────
    matched: list[tuple[Rule, int]] = []
    skipped: list[dict[str, Any]] = []

    for rule in ruleset.rules:
        missing = rule.missing_fields(record)
        if missing:
            skipped.append({
                "rule_id": rule.id,
                "title": rule.title,
                "missing_fields": missing,
                "reason": (
                    f"needs {', '.join(missing)}, which this scan did not "
                    f"collect — scored as absent, not as a problem"
                ),
            })
            continue
        if predicate.evaluate(rule.when, record):
            matched.append((rule, rule.weight_for(record)))

    # Deterministic order before any capping, so the score never depends on
    # where a rule happens to sit in the YAML file.
    matched.sort(key=lambda pair: (-pair[1], pair[0].id))

    # ── Family de-duplication ───────────────────────────────────────────────
    # Several symptoms of one underlying problem should not score in full three
    # times over.
    per_family: dict[str, int] = {}
    contributions: list[Contribution] = []
    bucket_totals: dict[str, int] = dict.fromkeys(ruleset.buckets, 0)

    for rule, raw_points in matched:
        seen_in_family = per_family.get(rule.family, 0)
        discounted = seen_in_family > 0 and rule.family != "positive"
        effective = (
            int(round(raw_points * ruleset.overlap_factor))
            if discounted else raw_points
        )
        per_family[rule.family] = seen_in_family + 1

        cap = ruleset.bucket_cap(rule.bucket)
        room = max(0, cap - bucket_totals.get(rule.bucket, 0))
        applied = min(effective, room)
        bucket_totals[rule.bucket] = bucket_totals.get(rule.bucket, 0) + applied

        contributions.append(Contribution(
            rule_id=rule.id,
            family=rule.family,
            bucket=rule.bucket,
            severity=rule.severity,
            confidence=rule.confidence,
            title=rule.title,
            points_raw=raw_points,
            points_applied=applied,
            capped=applied < effective,
            family_discounted=discounted,
            why=_render(rule.why, record),
            remediation=_render(rule.remediation, record),
            evidence=_evidence_for(rule, record),
        ))

    raw_score = min(ruleset.max_score, sum(bucket_totals.values()))

    # ── Modifiers ───────────────────────────────────────────────────────────
    # The product is clamped: modifiers stack multiplicatively, so two of them
    # (a WAF at 0.45 and a Cloudflare alias port at 0.25) would otherwise
    # multiply out to 0.11 and annihilate the score entirely. Mitigations should
    # reduce urgency, not erase a finding.
    applied_modifiers: list[AppliedModifier] = []
    product = 1.0
    for modifier in ruleset.modifiers:
        if predicate.evaluate(modifier.when, record):
            product *= modifier.factor
            applied_modifiers.append(AppliedModifier(
                id=modifier.id, factor=modifier.factor, reason=modifier.reason))

    mitigated = any(m.factor < 1.0 for m in applied_modifiers)
    product = max(ruleset.modifier_floor, product) if mitigated else product

    final = int(round(min(ruleset.max_score, raw_score * product)))
    band = ruleset.band_for(final)

    # ── Severity floor ──────────────────────────────────────────────────────
    # A triggered critical rule cannot end up in a trivial band — otherwise a
    # WAF in front of an end-of-life operating system would make it read as
    # low risk.
    #
    # But the floor applies ONLY when nothing mitigating fired. If a WAF is
    # genuinely blocking the request, or the port is a Cloudflare alias of a site
    # already counted, then the reduced score is the honest answer and forcing it
    # back up would put a third of the estate in "high" and make the band
    # meaningless. The finding itself still carries critical severity and stays
    # visible in the Findings view, so nothing is hidden either way.
    floored_from = ""
    worst_severity = _worst_severity(contributions)
    if ruleset.severity_floor and not mitigated and worst_severity == "critical" and \
                ruleset.band_rank(band) > ruleset.band_rank(ruleset.severity_floor):
        floored_from = band
        band = ruleset.severity_floor

    coverage, _absent = coverage_of(record)
    confidence = "high" if coverage >= 0.8 else "medium" if coverage >= 0.5 else "low"

    return ScoreResult(
        score=final,
        band=band,
        buckets=bucket_totals,
        raw_score=raw_score,
        contributions=contributions,
        modifiers=applied_modifiers,
        skipped=skipped,
        floored_from=floored_from,
        worst_severity=worst_severity,
        mitigated=mitigated,
        confidence=confidence,
        coverage=round(coverage, 3),
    )


def score_host(endpoint_results: list[ScoreResult]) -> dict[str, Any]:
    """Roll endpoint scores up to a host.

    Deliberately *not* an average: a host with one terrible endpoint and nine
    clean ones is not 90% healthy. The worst endpoint sets the floor, with a
    small logarithmic bump for breadth so a host with many distinct problems
    ranks above one with a single problem of the same severity.
    """
    live = [r for r in endpoint_results if not r.excluded]
    if not live:
        return {"score": 0, "band": "info", "worst": 0, "finding_count": 0}

    worst = max(r.score for r in live)
    distinct = len({c.rule_id for r in live for c in r.findings})
    bump = min(10, int(round(2 * math.log1p(distinct)))) if distinct > 1 else 0

    return {
        "score": min(100, worst + bump),
        "worst": worst,
        "breadth_bonus": bump,
        "finding_count": distinct,
    }


def residual_risk_index(results: list[ScoreResult], ruleset: RuleSet) -> dict[str, Any]:
    """A single 0-100 headline where higher is better.

    Weighted by band rather than raw score, so one critical endpoint moves the
    number more than a long tail of low ones. The formula is exposed in the
    Methodology view — an index nobody can reproduce is worse than no index.
    """
    live = [r for r in results if not r.excluded]
    if not live:
        return {"index": 100, "endpoints": 0, "weighted": 0.0, "by_band": {}}

    weights = {"critical": 1.0, "high": 0.6, "medium": 0.3, "low": 0.1, "info": 0.0}
    by_band: dict[str, int] = {}
    weighted = 0.0
    for result in live:
        by_band[result.band] = by_band.get(result.band, 0) + 1
        weighted += weights.get(result.band, 0.0)

    index = int(round(100 * (1 - min(1.0, weighted / len(live)))))
    return {
        "index": index,
        "endpoints": len(live),
        "weighted": round(weighted, 2),
        "by_band": by_band,
        "formula": (
            "100 x (1 - sum(band weight) / endpoints), with weights "
            "critical 1.0, high 0.6, medium 0.3, low 0.1, info 0. "
            "Excluded scan artefacts are not counted."
        ),
    }
