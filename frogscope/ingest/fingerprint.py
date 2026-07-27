"""Match passive product fingerprints against an endpoint record.

Deliberately narrow: this reads only fields a scan already returned. Nothing here
requests a path, so a panel living at `/admin` on a host whose root page is a
marketing site is invisible — and the coverage report says so rather than letting
a clean result imply there is nothing there.

The output feeds two different things and they must not be confused:

* `panel_*` fields say WHAT the product is. That is inventory.
* the rules in `rules.yaml` decide whether it MATTERS. That is scoring.

Keeping them apart is what lets "we found a Grafana" and "a public Grafana is
worth 30 points" be argued about separately.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

# How much authority the product carries if it really is reachable. Separate from
# match confidence: we may be certain it is Grafana and still rank it below a
# Jenkins we are only fairly sure about.
GROUP_EXPOSURE = {
    "ci_cd": "critical",
    "infra_console": "critical",
    "database_ui": "critical",
    "network_device": "high",
    "storage": "high",
    "admin_panel": "high",
    "dev_tool": "medium",
    "monitoring": "medium",
    "webmail": "medium",
    "iot": "medium",
}

_CONFIDENCE_RANK = {"confirmed": 3, "probable": 2, "possible": 1}
_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass
class Matcher:
    """One compiled fingerprint."""

    id: str
    label: str
    group: str = ""
    product: str = ""
    confidence: str = "probable"
    severity: str = ""
    note: str = ""
    why: str = ""
    requires_fields: tuple[str, ...] = ()
    title: tuple[re.Pattern, ...] = ()
    body: tuple[re.Pattern, ...] = ()
    server: tuple[re.Pattern, ...] = ()
    tech: frozenset[str] = frozenset()
    cpe: frozenset[str] = frozenset()
    favicon: frozenset[str] = frozenset()
    ports: frozenset[int] = frozenset()
    # When true, a technology or CPE match alone is NOT enough — the title must
    # also match. This exists because "the site runs WordPress" is not "the
    # WordPress admin panel is exposed": on a real estate, matching the platform
    # name flagged 66 ordinary marketing pages and zero actual admin panels.
    require_title: bool = False

    def evaluate(self, rec: dict) -> tuple[bool, str, str]:
        """Return (matched, which_signal, observed_value).

        Reporting the signal and the observed value is what makes a match
        auditable. "Jenkins because the title was 'Dashboard [Jenkins]'" can be
        argued with; a bare boolean cannot.
        """
        # A port constraint narrows an otherwise-loose match; on its own it would
        # flag every host that happens to answer there.
        if self.ports and int(rec.get("port") or 0) not in self.ports:
            return False, "", ""

        title = str(rec.get("title") or "")
        for pattern in self.title:
            found = pattern.search(title)
            if found:
                return True, "title", title[:200]

        # Everything below is weaker evidence than the title. For products where
        # the platform name says nothing about whether the admin surface is
        # reachable, stop here rather than reporting the site as a panel.
        if self.require_title:
            return False, "", ""

        for pattern in self.server:
            value = str(rec.get("webserver") or "")
            if value and pattern.search(value):
                return True, "server header", value[:120]

        if self.tech:
            names = {str(t).lower() for t in (rec.get("tech_names") or rec.get("tech") or [])}
            hit = self.tech & names
            if hit:
                return True, "technology", ", ".join(sorted(hit))

        if self.cpe:
            products = {str(c).lower() for c in (rec.get("cpe_products") or [])}
            hit = self.cpe & products
            if hit:
                return True, "CPE product", ", ".join(sorted(hit))

        if self.favicon:
            digest = str(rec.get("favicon_md5") or "").lower()
            if digest and digest in self.favicon:
                return True, "favicon hash", digest

        # Body last: it is the most specific signal but also the one most often
        # absent, since it needs httpx -body-preview.
        body = str(rec.get("body_preview") or "")
        if body:
            for pattern in self.body:
                found = pattern.search(body)
                if found:
                    return True, "response body", found.group(0)[:120]

        return False, "", ""

    def missing_fields(self, rec: dict) -> list[str]:
        """Fields this matcher needs that the scan did not collect."""
        return [f for f in self.requires_fields if not rec.get(f)]


@dataclass
class Catalogue:
    version: int = 0
    panels: list[Matcher] = field(default_factory=list)
    default_pages: list[Matcher] = field(default_factory=list)
    disclosure: list[Matcher] = field(default_factory=list)
    storage: list[Matcher] = field(default_factory=list)

    @property
    def total(self) -> int:
        return (len(self.panels) + len(self.default_pages)
                + len(self.disclosure) + len(self.storage))

    def all_matchers(self) -> list[Matcher]:
        return [*self.panels, *self.default_pages, *self.disclosure, *self.storage]


def _compile(patterns) -> tuple[re.Pattern, ...]:
    out = []
    for raw in patterns or []:
        try:
            out.append(re.compile(str(raw), re.I))
        except re.error:
            # A broken pattern must not take the whole ingest down, but it must
            # not silently match everything either — it is dropped and reported
            # by `frogscope catalogue validate`.
            continue
    return tuple(out)


def _matcher(entry: dict, *, kind: str) -> Matcher:
    return Matcher(
        id=entry["id"],
        label=entry.get("label") or entry.get("product") or entry["id"],
        group=entry.get("group", kind),
        product=entry.get("product", ""),
        confidence=entry.get("confidence", "probable"),
        severity=entry.get("severity", ""),
        note=(entry.get("note") or "").strip(),
        why=(entry.get("why") or "").strip(),
        requires_fields=tuple(entry.get("requires_fields") or ()),
        title=_compile(entry.get("title")),
        body=_compile(entry.get("body")),
        server=_compile(entry.get("server")),
        tech=frozenset(str(t).lower() for t in entry.get("tech") or ()),
        cpe=frozenset(str(c).lower() for c in entry.get("cpe") or ()),
        favicon=frozenset(str(f).lower() for f in entry.get("favicon") or ()),
        ports=frozenset(int(p) for p in entry.get("port") or ()),
        require_title=bool(entry.get("require_title")),
    )


@lru_cache(maxsize=8)
def load_catalogue(config_dir: Path | str) -> Catalogue:
    path = Path(config_dir) / "fingerprints.yaml"
    if not path.exists():
        return Catalogue()
    doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return Catalogue(
        version=int(doc.get("version") or 0),
        panels=[_matcher(e, kind="panel") for e in doc.get("panels") or []],
        default_pages=[_matcher(e, kind="default_page")
                       for e in doc.get("default_pages") or []],
        disclosure=[_matcher(e, kind="disclosure")
                    for e in doc.get("disclosure") or []],
        storage=[_matcher(e, kind="storage")
                 for e in doc.get("storage_exposure") or []],
    )


def identify(rec: dict, catalogue: Catalogue) -> dict[str, Any]:
    """Annotate one record with everything the catalogue recognises.

    Returns fields, never mutates. A record can legitimately match several
    entries — a Tomcat default page that is also a manager console — so every hit
    is kept and the worst drives the summary fields.
    """
    hits: list[dict[str, Any]] = []
    skipped: list[str] = []

    for matcher in catalogue.all_matchers():
        absent = matcher.missing_fields(rec)
        if absent:
            # Reported, not scored. Silently passing a check the scan could not
            # perform is how a dashboard reassures people about data it never had.
            skipped.append(f"{matcher.id} needs {', '.join(absent)}")
            continue
        matched, signal, observed = matcher.evaluate(rec)
        if not matched:
            continue
        hits.append({
            "id": matcher.id,
            "label": matcher.label,
            "product": matcher.product,
            "group": matcher.group,
            "confidence": matcher.confidence,
            "severity": matcher.severity or GROUP_EXPOSURE.get(matcher.group, ""),
            "signal": signal,
            "observed": observed,
            "note": matcher.note,
            "why": matcher.why,
        })

    panels = [h for h in hits if h["id"].startswith("PANEL_")]
    defaults = [h for h in hits if h["id"].startswith("DEFAULT_")]
    disclosure = [h for h in hits if h["id"].startswith("DISCLOSE_")]
    storage = [h for h in hits if h["id"].startswith("STORAGE_")]

    best = _best(panels)
    worst_disclosure = _worst_severity(disclosure + storage)

    return {
        "fingerprint_hits": hits,
        "fingerprint_count": len(hits),
        "fingerprint_skipped": skipped,

        "panel_product": best["product"] if best else "",
        "panel_group": best["group"] if best else "",
        "panel_exposure": best["severity"] if best else "",
        "panel_confidence": best["confidence"] if best else "",
        "panel_count": len(panels),
        "panel_products": sorted({h["product"] for h in panels if h["product"]}),
        "panel_groups": sorted({h["group"] for h in panels}),

        "default_page_product": defaults[0]["product"] if defaults else "",
        "is_default_page": bool(defaults),

        "disclosure_ids": sorted({h["id"] for h in disclosure + storage}),
        "disclosure_count": len(disclosure) + len(storage),
        "disclosure_worst": worst_disclosure,
    }


def _best(hits: list[dict]) -> dict | None:
    """Most exposing product first, then most confident match.

    Sorting by exposure before confidence is deliberate: a probable Jenkins
    matters more than a confirmed webmail, and the summary field is what the grid
    and the KPI tiles read.
    """
    if not hits:
        return None
    return sorted(
        hits,
        key=lambda h: (
            -_SEVERITY_RANK.get(h["severity"], 0),
            -_CONFIDENCE_RANK.get(h["confidence"], 0),
            h["id"],
        ),
    )[0]


def _worst_severity(hits: list[dict]) -> str:
    if not hits:
        return ""
    return max((h["severity"] for h in hits if h["severity"]),
               key=lambda s: _SEVERITY_RANK.get(s, 0), default="")


def coverage(catalogue: Catalogue, present_fields: set[str]) -> dict[str, Any]:
    """Which parts of the catalogue this scan's data can actually reach.

    Three states, because collapsing them hides the interesting one:

    * evaluable  — every signal it uses is available
    * partial    — some signals available, others not, so it can fire but with
                   less evidence than it was written to use
    * blocked    — none of its signals are available, so a clean result from it
                   means nothing at all

    The honest answer to "we found no exposed panels" needs the third number.
    """
    evaluable, partial, blocked = [], [], {}
    needed: dict[str, int] = {}

    for matcher in catalogue.all_matchers():
        # What this matcher could use, and whether the data is there.
        signals = {
            "title": bool(matcher.title),
            "tech": bool(matcher.tech),
            "cpe": bool(matcher.cpe),
            "server": bool(matcher.server),
            "body": bool(matcher.body),
            "favicon": bool(matcher.favicon),
        }
        availability = {
            "title": "title" in present_fields,
            "tech": "tech_names" in present_fields,
            "cpe": "cpe_products" in present_fields,
            "server": "webserver" in present_fields,
            "body": "body_preview" in present_fields,
            "favicon": "favicon_md5" in present_fields,
        }
        declared_missing = [f for f in matcher.requires_fields
                            if f not in present_fields]

        usable = [name for name, used in signals.items()
                  if used and availability[name]]
        unusable = [name for name, used in signals.items()
                    if used and not availability[name]]

        if declared_missing or not usable:
            reasons = declared_missing or [
                {"body": "body_preview", "favicon": "favicon_md5"}.get(n, n)
                for n in unusable
            ]
            blocked[matcher.id] = reasons
            for reason in reasons:
                needed[reason] = needed.get(reason, 0) + 1
        elif unusable:
            partial.append(matcher.id)
        else:
            evaluable.append(matcher.id)

    return {
        "catalogue_version": catalogue.version,
        "total": catalogue.total,
        "evaluable": len(evaluable),
        "partial": len(partial),
        "blocked": len(blocked),
        "blocked_by_field": dict(sorted(needed.items(), key=lambda kv: -kv[1])),
        "blocked_ids": sorted(blocked),
        "partial_ids": sorted(partial),
    }
