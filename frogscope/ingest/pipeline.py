"""Ingest orchestration: read -> normalise -> collapse -> enrich -> store.

Everything happens in one transaction, so a failure part-way leaves no partial
run behind.
"""

from __future__ import annotations

import gzip
import json
import shutil
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

from ..config import Config
from . import diff as diff_mod
from . import enrich as enrich_mod
from . import loader, quality, rollup, store, timeseries
from .normalize import collapse_intra_run, content_hash


class DuplicateRun(Exception):
    """Raised when the same file, or the same content, is already ingested."""

    def __init__(self, message: str, existing: sqlite3.Row):
        super().__init__(message)
        self.existing = existing


class IncompleteScan(Exception):
    """Raised when the source file looks like a scan still in progress.

    `override` names the flag that would accept it anyway. Two different gates
    reach this exception and they need DIFFERENT overrides: a truncated-looking
    file needs `allow_incomplete`, a suspicious change in scale needs
    `allow_drift`. Reporting only one of them left the UI offering a button that
    could never work.
    """

    override = "allow_incomplete"

    def __init__(self, message: str, warnings: list[str],
                 override: str | None = None):
        super().__init__(message)
        self.warnings = warnings
        if override:
            self.override = override


class ScaleDrift(IncompleteScan):
    """The run is a very different size from the previous one.

    A subclass so existing `except IncompleteScan` callers keep working, but the
    override it asks for is the one that actually ungates it.
    """

    override = "allow_drift"


class TruncationSuspected(ScaleDrift):
    """A scan submitted essentially the same host list as its predecessor but
    produced a wildly different endpoint count — the signature of a scanner
    subprocess dying partway through, not a real change in the estate.

    A subclass of `ScaleDrift` so existing `except ScaleDrift`/`IncompleteScan`
    callers keep working, but with its own override: `allow_drift` must NOT
    ungate this (that flag is what let this exact failure mode go silently
    ingested before — see `scan/executor.py`), only an explicit
    `confirm_truncation` should.
    """

    override = "confirm_truncation"


@dataclass
class IngestResult:
    run_id: int
    run_key: str
    project_id: int
    row_count: int
    endpoint_count: int
    host_count: int
    collapse: dict[str, Any]
    warnings: list[str] = field(default_factory=list)
    missing_columns: list[str] = field(default_factory=list)
    unknown_columns: list[str] = field(default_factory=list)
    suggestions: list[dict] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)
    risk: dict[str, Any] = field(default_factory=dict)
    diff: dict[str, Any] = field(default_factory=dict)


def _run_key(records: list[dict], label: str | None, content_sha: str,
             fallback_time: str | None = None) -> str:
    stamps = [r.get("scanned_at") for r in records if r.get("scanned_at")]
    when = None
    if stamps:
        try:
            when = datetime.fromisoformat(max(stamps))
        except ValueError:
            when = None
    if when is None and fallback_time:
        # Some scanner versions omit per-row timestamps. The run key and the
        # timeline are both derived from them, so "unknown" would put the run
        # nowhere in the ordering — a scan we supervised can supply the real time.
        try:
            when = datetime.fromisoformat(fallback_time)
        except ValueError:
            when = None
    stamp = when.strftime("%Y%m%dT%H%MZ") if when else "unknown"
    slug = (label or "run").strip().lower().replace(" ", "-")[:24] or "run"
    return f"run-{stamp}__{slug}__{content_sha[:8]}"


def _window(records: list[dict]) -> tuple[str | None, str | None, float | None]:
    stamps = sorted(r["scanned_at"] for r in records if r.get("scanned_at"))
    if not stamps:
        return None, None, None
    first, last = stamps[0], stamps[-1]
    duration = None
    try:
        duration = (
            datetime.fromisoformat(last) - datetime.fromisoformat(first)
        ).total_seconds()
    except ValueError:
        pass
    return first, last, duration


def _load_cloud_ranges(cfg: Config) -> dict[str, list] | None:
    """Read the local cache `frogscope/scan/cloud_ranges.py` wrote — pure
    file I/O, no network call, matching the ingest-is-offline house rule.
    None if the config declaring providers is missing, or nothing has been
    fetched yet; `dangling_a_record`/`in_claimable_range` simply stay false
    for every address in that case, exactly like a rule with a missing
    `requires_fields` input."""
    from . import correlate as correlate_mod

    yaml_path = cfg.config_dir / "cloud_ranges.yaml"
    if not yaml_path.exists():
        return None
    try:
        spec = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError:
        return None
    provider_ids = spec.get("claimable_provider_ids") or []
    cache_rel = (spec.get("cache") or {}).get("path") or "cache/cloud_ranges.json"
    return correlate_mod.load_cached_ranges(cfg.data_dir / cache_rel, provider_ids)


def _summarise(records: list[dict], rollups: list[dict], entities=None) -> dict[str, Any]:
    def count(predicate) -> int:
        return sum(1 for r in records if predicate(r))

    real = [r for r in records
            if not r.get("scan_artifact") and not r.get("cf_alias_port")]
    by_class: dict[str, int] = {}
    for rec in records:
        key = rec.get("response_class") or "unknown"
        by_class[key] = by_class.get(key, 0) + 1

    by_env: dict[str, int] = {}
    for r in rollups:
        key = r.get("env") or "unclassified"
        by_env[key] = by_env.get(key, 0) + 1

    return {
        "endpoints": len(records),
        "hosts": len(rollups),
        "real_endpoints": len(real),
        "scan_artifacts": count(lambda r: r.get("scan_artifact")),
        "cf_alias_ports": count(lambda r: r.get("cf_alias_port")),
        "serving": count(lambda r: r.get("serves_content")),
        "origin_exposed": count(lambda r: r.get("origin_exposed")),
        "origin_exposed_hosts": sum(1 for r in rollups if r.get("origin_exposed")),
        "no_waf": count(lambda r: r.get("no_waf")),
        "no_waf_hosts": sum(1 for r in rollups if r.get("no_waf_count")),
        "waf_protected": count(lambda r: r.get("waf_protected")),
        "cdn_bypass_hosts": sum(1 for r in rollups if r.get("cdn_bypass_candidate")),
        "auth_surfaces": count(lambda r: r.get("auth_surface_type", "none") != "none"),
        "mgmt_surfaces": count(lambda r: r.get("mgmt_surface")),
        "remote_access": count(lambda r: r.get("remote_access_exposed")),
        "azure_app_proxy": count(lambda r: r.get("azure_app_proxy")),
        "cleartext_no_upgrade": count(lambda r: r.get("no_tls_redirect")),
        "unprotected": count(lambda r: r.get("unprotected")),
        "nonprod_exposed": count(lambda r: r.get("is_nonprod_exposed")),
        "broken_origin": count(
            lambda r: r.get("origin_health") not in ("ok", "unknown", None)
        ),
        "unique_ips": len({r.get("host_ip") for r in records if r.get("host_ip")}),
        "ports": sorted({int(r["port"]) for r in records}),
        "by_response_class": dict(sorted(by_class.items(), key=lambda kv: -kv[1])),
        "by_env": dict(sorted(by_env.items(), key=lambda kv: -kv[1])),
        **_correlation_summary(entities),
    }


def _correlation_summary(entities) -> dict[str, Any]:
    """Empty (not absent) when correlation didn't run, so the exec page's
    caveat logic can tell "ran and found nothing" apart from "never ran" by
    checking `runs.correlated` — these counts alone can't distinguish that."""
    if entities is None:
        return {}
    return {
        "unique_asns": 0,  # no ASN data in this release, see cloud_ranges.yaml
        "unique_cidrs": len(entities.cidr_blocks),
        "certs": len(entities.certificates),
        "certs_expiring_30d": sum(
            1 for c in entities.certificates
            if c.get("days_remaining") is not None and 0 <= c["days_remaining"] <= 30
        ),
        "certs_expired": sum(1 for c in entities.certificates if c.get("expired")),
        "discovered_via_cert": sum(
            1 for n in entities.cert_names if n.get("discovered_new") and not n.get("in_scope")
        ),
        "hosts_in_claimable_ranges": sum(
            1 for e in entities.ip_addresses if e.get("in_claimable_range")
        ),
        "foreign_shared_ips": sum(
            1 for e in entities.ip_addresses if e.get("foreign_domain_count", 0) > 0
        ),
    }


def analyse(path: Path | str, cfg: Config, ruleset=None, *,
            correlation=None, known_names: frozenset[str] = frozenset(),
            cloud_ranges: dict[str, list] | None = None
            ) -> tuple[list[dict], list[dict], loader.LoadResult, Any, Any]:
    """Read, derive, and score without touching the database.

    `validate` uses this too, so the CLI can show exactly what an ingest would
    produce before anything is written. `known_names`/`cloud_ranges` are
    passed in as plain data (never fetched here) so that contract holds even
    when v2 correlation is in play — `ingest()` is the only caller allowed to
    touch the database or, transitively via `frogscope/scan/cloud_ranges.py`,
    the network.

    `correlation` attaches BEFORE scoring, not after: several scoring rules
    (`CERT_SELF_SIGNED`, `DANGLING_A_RECORD`, ...) read the fields it
    projects onto each record, via `SCORABLE_FIELDS`.
    """
    from ..scoring import engine as score_engine
    from ..scoring import lifecycle as lifecycle_mod
    from ..scoring.rules import load_ruleset

    result = loader.load(path)
    records, collapse = collapse_intra_run(result.records)

    correlate_mod = None
    if correlation is not None:
        from . import correlate as correlate_mod
    ptr_by_ip = correlate_mod.ptr_map(correlation) if correlate_mod else {}
    enrich_mod.enrich(records, cfg, ptr_by_ip=ptr_by_ip)

    entities = None
    if correlate_mod is not None:
        our_domains = correlate_mod.domains_from_records(
            records, cfg.multi_label_tlds,
            ptr_resolved_hosts=frozenset(correlation.ptr_resolved_hosts),
            explicit_domains=frozenset(correlation.scan_domains))
        entities = correlate_mod.build_entities(
            correlation, our_domains=our_domains,
            multi_label_tlds=cfg.multi_label_tlds, known_names=known_names,
            cloud_ranges=cloud_ranges)
        correlate_mod.attach(records, entities)

    ruleset = ruleset or load_ruleset(cfg.config_dir)
    for record in records:
        lifecycle_mod.derive_scoring_inputs(
            record, ruleset.lifecycle, ruleset.takeover)

    scored: list[tuple[dict, Any]] = []
    for record in records:
        outcome = score_engine.score_record(record, ruleset)
        scored.append((record, outcome))

        record["risk_score"] = outcome.score
        record["risk_band"] = outcome.band
        record["risk_excluded"] = outcome.excluded
        record["risk_confidence"] = outcome.confidence
        record["risk_coverage"] = outcome.coverage
        record["exposure"] = outcome.buckets.get("exposure", 0)
        record["hygiene"] = outcome.buckets.get("hygiene", 0)
        record["sensitivity"] = outcome.buckets.get("sensitivity", 0)
        record["finding_count"] = len(outcome.findings)
        record["top_finding"] = (
            outcome.findings[0].title if outcome.findings else "")
        record["worst_severity"] = outcome.worst_severity
        record["risk_mitigated"] = outcome.mitigated

    rollups = rollup.build_host_rollups(records, cfg)
    _attach_host_scores(rollups, scored, score_engine)
    if entities is not None:
        _attach_host_correlation(rollups, records)

    return records, rollups, result, collapse, entities


def _attach_host_scores(rollups: list[dict], scored: list[tuple[dict, Any]],
                        score_engine) -> None:
    """Roll endpoint scores up per host, using max-plus-breadth rather than a
    mean — a host with one terrible endpoint is not 90% healthy."""
    by_host: dict[str, list] = {}
    worst_endpoint: dict[str, tuple[int, str]] = {}
    for record, outcome in scored:
        by_host.setdefault(record["host"], []).append(outcome)
        current = worst_endpoint.get(record["host"])
        if current is None or outcome.score > current[0]:
            worst_endpoint[record["host"]] = (outcome.score, record["endpoint_key"])

    for entry in rollups:
        results = by_host.get(entry["host"], [])
        summary = score_engine.score_host(results)
        entry["risk_score"] = summary["score"]
        entry["finding_count"] = summary["finding_count"]
        entry["breadth_bonus"] = summary.get("breadth_bonus", 0)
        entry["worst_endpoint"] = worst_endpoint.get(entry["host"], (0, ""))[1]
        bands = [r.band for r in results if not r.excluded]
        order = ["critical", "high", "medium", "low", "info"]
        entry["risk_band"] = next((b for b in order if b in bands), "info")


def _attach_host_correlation(rollups: list[dict], records: list[dict]) -> None:
    """Roll the per-endpoint correlation scalars `correlate.attach()` wrote
    up to host grain: every CIDR/PTR/cert this host's endpoints touched, the
    worst certificate state, and whether any of its addresses sit in a
    claimable cloud range."""
    by_host: dict[str, list[dict]] = {}
    for rec in records:
        by_host.setdefault(rec["host"], []).append(rec)

    order = ["expired", "self_signed", "mismatched", "untrusted", "revoked", "ok"]
    for entry in rollups:
        group = by_host.get(entry["host"], [])
        cidrs = sorted({r["cidr"] for r in group if r.get("cidr")})
        ptrs = sorted({r["ptr_host"] for r in group if r.get("ptr_host")})
        certs = sorted({r["cert_sha256"] for r in group if r.get("cert_sha256")})
        entry["cidrs"] = cidrs
        entry["ptr_names"] = ptrs
        entry["certs"] = certs

        remaining = [r["cert_days_remaining"] for r in group
                    if r.get("cert_days_remaining") is not None]
        entry["min_cert_days_remaining"] = min(remaining) if remaining else None

        states: set[str] = set()
        for r in group:
            if r.get("cert_expired"):
                states.add("expired")
            if r.get("cert_self_signed"):
                states.add("self_signed")
            if r.get("cert_mismatched"):
                states.add("mismatched")
            if r.get("cert_untrusted"):
                states.add("untrusted")
            if r.get("cert_revoked"):
                states.add("revoked")
        entry["worst_cert_state"] = next((s for s in order if s in states), "")

        entry["max_ip_foreign_domains"] = max(
            (r.get("ip_foreign_domain_count", 0) for r in group), default=0)
        entry["in_claimable_range"] = any(r.get("in_claimable_range") for r in group)


def _store_correlation(conn: sqlite3.Connection, project_id: int, run_id: int,
                       entities, corr) -> None:
    """Write every v2 correlation entity inside the caller's transaction, so
    a failure here leaves no more of a partial run than a failure anywhere
    else in `ingest()` would."""
    ip_assets = store.upsert_assets(
        conn, project_id, run_id, "ip",
        [(e["ip"], e["ip"]) for e in entities.ip_addresses])
    cidr_assets = store.upsert_assets(
        conn, project_id, run_id, "cidr",
        [(b["cidr"], b["cidr"]) for b in entities.cidr_blocks])
    cert_assets = store.upsert_assets(
        conn, project_id, run_id, "cert",
        [(c["cert_sha256"], c.get("subject_cn") or c["cert_sha256"])
         for c in entities.certificates])

    store.insert_ip_addresses(conn, run_id, entities.ip_addresses, ip_assets)
    store.insert_dns_records(conn, run_id, entities.dns_records)
    store.insert_cidr_blocks(conn, run_id, entities.cidr_blocks, cidr_assets)
    store.insert_certificates(conn, run_id, entities.certificates, cert_assets)
    store.insert_cert_names(conn, run_id, entities.cert_names)
    store.insert_cert_observations(conn, run_id, entities.cert_observations)

    collectors = [
        {"tool": tool, **info} for tool, info in (corr.collectors or {}).items()
    ] if corr else []
    if collectors:
        store.insert_run_collectors(conn, run_id, collectors)


def ingest(conn: sqlite3.Connection, cfg: Config, path: Path | str, *,
           project: str = "default", project_name: str | None = None,
           label: str | None = None, run_kind: str = "adhoc",
           force: bool = False, allow_incomplete: bool = False,
           allow_drift: bool = False, confirm_truncation: bool = False,
           keep_raw: bool = True,
           trust_mtime: bool = True, supervised: bool = False,
           scanned_at: str | None = None,
           hosts_submitted: int | None = None,
           ports_prescoped: bool | None = None,
           correlation=None) -> IngestResult:
    """`correlation`: a path to (or already-loaded) `correlation.json` sidecar
    from an opt-in correlated scan — see `ScanRun._correlate` and
    `ingest/correlate.py`. None for an ordinary scan or upload; every v2
    field simply stays empty, exactly like an unset httpx flag today.
    """
    from ..scoring import findings as findings_mod
    from ..scoring.engine import residual_risk_index
    from ..scoring.rules import load_ruleset, rules_fingerprint

    path = Path(path)
    ruleset = load_ruleset(cfg.config_dir)

    # Resolved before analyse() so a correlated scan can look up this
    # project's history — analyse() itself never touches the database, so
    # anything it needs from prior runs has to arrive as plain data.
    project_id = store.upsert_project(conn, project, project_name)

    corr = None
    known_names: frozenset[str] = frozenset()
    cloud_ranges = None
    if correlation is not None:
        from . import correlate as correlate_mod

        corr = correlate_mod.load(correlation)
        known_names = frozenset(
            row["name"] for row in conn.execute(
                "SELECT DISTINCT name FROM dns_records dr "
                "JOIN runs r ON r.id = dr.run_id WHERE r.project_id = ? "
                "UNION "
                "SELECT DISTINCT name FROM cert_names cn "
                "JOIN runs r ON r.id = cn.run_id WHERE r.project_id = ?",
                (project_id, project_id),
            )
        )
        cloud_ranges = _load_cloud_ranges(cfg)

    records, rollups, load_result, collapse, entities = analyse(
        path, cfg, ruleset, correlation=corr, known_names=known_names,
        cloud_ranges=cloud_ranges)
    if not records:
        raise ValueError(f"{path} produced no usable endpoint records")

    warnings = list(load_result.warnings)

    prev = store.previous_run(conn, project_id)
    previous_ports: set[int] | None = None
    previous_count: int | None = None
    if prev:
        previous_count = prev["endpoint_count"]
        try:
            previous_ports = set(
                (json.loads(prev["summary_json"] or "{}") or {}).get("ports") or []
            )
        except json.JSONDecodeError:
            previous_ports = None

    # A browser upload is written to a temp file at request time, so its mtime is
    # always "a moment ago" and the check would fire on every single upload —
    # training people to tick the override permanently and thereby defeating a
    # guard that exists for a real reason. The timestamps inside the file, and the
    # port-subset comparison, stay meaningful either way.
    completeness = quality.completeness_check(
        records,
        source_mtime=path.stat().st_mtime if trust_mtime else None,
        previous_ports=previous_ports,
        # We started the scanner and saw it exit, so "might still be running" is
        # not a possibility that needs guessing about.
        supervised=supervised,
    )
    if completeness and not allow_incomplete:
        raise IncompleteScan(
            "this looks like a scan that is still running, so ingesting it now "
            "would store a truncated run",
            completeness,
        )
    warnings.extend(completeness)

    drift, suspected_truncation = quality.truncation_check(
        len(records), previous_count,
        hosts_submitted=hosts_submitted,
        previous_hosts_submitted=prev["hosts_submitted"] if prev else None,
        ports_prescoped=ports_prescoped,
        previous_ports_prescoped=prev["ports_prescoped"] if prev else None,
    )
    if drift and suspected_truncation and not confirm_truncation:
        raise TruncationSuspected(f"suspicious change in scale: {drift}", [drift])
    if drift and not suspected_truncation and not allow_drift:
        raise ScaleDrift(f"suspicious change in scale: {drift}", [drift])
    if drift:
        warnings.append(drift)

    content_sha = content_hash(records)
    existing = store.find_duplicate(conn, project_id, load_result.raw_sha256, content_sha)
    if existing and not force:
        raise DuplicateRun(
            f"this content was already ingested as run id {existing['run_id']} "
            f"on {existing['ingested_at']}; pass --force to ingest it again",
            existing,
        )

    from ..scoring import engine as score_engine
    scored = [(r, score_engine.score_record(r, ruleset)) for r in records]
    finding_list = findings_mod.build_findings(scored)
    risk_summary = {
        **findings_mod.summarise(finding_list),
        "residual_risk": residual_risk_index([s for _r, s in scored], ruleset),
        "by_band": _band_counts(scored),
        "by_worst_severity": _severity_counts(scored),
        "skipped_rules": _skipped_rules(scored),
    }

    started, completed, duration = _window(records)
    summary = _summarise(records, rollups, entities)
    summary["risk"] = risk_summary
    run_key = _run_key(records, label, content_sha, fallback_time=scanned_at)
    if force and existing:
        run_key = f"{run_key}__dup"

    meta = {
        "run_key": run_key,
        "label": label,
        "run_kind": "baseline" if prev is None else run_kind,
        "started_at": started,
        "completed_at": completed,
        "scan_duration_s": duration,
        "source_file": path.name,
        "raw_sha256": load_result.raw_sha256,
        "content_sha256": content_sha,
        "byte_count": load_result.byte_count,
        "row_count": load_result.row_count,
        "endpoint_count": len(records),
        "host_count": len(rollups),
        "config_hash": cfg.config_hash,
        "is_baseline": prev is None,
        "duplicate_of": existing["run_id"] if (existing and force) else None,
        "incomplete": bool(completeness),
        "warnings": warnings,
        "summary": summary,
        "rules_hash": rules_fingerprint(ruleset),
        "rules_version": ruleset.version,
        "risk_summary": risk_summary,
        "hosts_submitted": hosts_submitted,
        "ports_prescoped": (None if ports_prescoped is None
                            else int(ports_prescoped)),
    }

    try:
        run_id = store.insert_run(conn, project_id, meta)

        endpoint_assets = store.upsert_assets(
            conn, project_id, run_id, "endpoint",
            [(r["endpoint_key"], r.get("host_display") or r["host"]) for r in records],
        )
        host_assets = store.upsert_assets(
            conn, project_id, run_id, "host",
            [(r["host"], r["host_display"]) for r in rollups],
        )

        store.insert_endpoints(conn, run_id, records, endpoint_assets)
        store.insert_host_rollups(conn, run_id, rollups, host_assets)
        store.insert_scores(conn, run_id, scored, endpoint_assets)
        finding_counts = findings_mod.upsert_findings(
            conn, project_id, run_id, finding_list)
        risk_summary["finding_lifecycle"] = finding_counts

        if entities is not None:
            _store_correlation(conn, project_id, run_id, entities, corr)
        conn.execute("UPDATE runs SET correlated = ? WHERE id = ?",
                    (1 if entities is not None else 0, run_id))

        # Diff against the run that precedes this one *by scan time*, so
        # backfilling an older file slots into the timeline correctly rather
        # than being compared against a newer scan.
        prev_id = diff_mod.previous_run_id(conn, project_id, run_id)
        diff_summary = diff_mod.diff_runs(
            conn, project_id, run_id, prev_id, cfg.diff)

        run_row = conn.execute("SELECT * FROM runs WHERE id = ?",
                               (run_id,)).fetchone()
        timeseries.materialise(conn, run_id, run_row)

        census = quality.column_census(
            [r.get("raw") or {} for r in load_result.records],
            load_result.source_columns,
        )
        store.insert_column_census(conn, run_id, census)
        store.record_ingest_file(conn, project_id, run_id, meta)
        conn.commit()
    except Exception:
        conn.rollback()
        raise

    if keep_raw:
        _archive(cfg, run_key, path)

    return IngestResult(
        run_id=run_id,
        run_key=run_key,
        project_id=project_id,
        row_count=load_result.row_count,
        endpoint_count=len(records),
        host_count=len(rollups),
        collapse=collapse.as_dict(),
        warnings=warnings,
        missing_columns=load_result.missing_columns,
        unknown_columns=load_result.unknown_columns,
        suggestions=quality.suggest_httpx_flags(census),
        summary=summary,
        risk=risk_summary,
        diff=diff_summary,
    )


def _archive(cfg: Config, run_key: str, path: Path) -> None:
    """Keep the source CSV gzipped, so the DB can be fully rebuilt later when
    enrichment or scoring logic improves. Better logic then means re-deriving
    history rather than losing it."""
    target_dir = cfg.raw_dir
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / f"{run_key}.csv.gz"
    if target.exists():
        return
    with path.open("rb") as src, gzip.open(target, "wb") as dst:
        shutil.copyfileobj(src, dst)


def _band_counts(scored: list[tuple[dict, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for _record, result in scored:
        if result.excluded:
            continue
        counts[result.band] = counts.get(result.band, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: -kv[1]))


def _severity_counts(scored: list[tuple[dict, Any]]) -> dict[str, int]:
    """Endpoints by their worst single issue, which is not the same question as
    the band distribution."""
    counts: dict[str, int] = {}
    for _record, result in scored:
        if result.excluded or not result.worst_severity:
            continue
        counts[result.worst_severity] = counts.get(result.worst_severity, 0) + 1
    order = ["critical", "high", "medium", "low", "info"]
    return {k: counts[k] for k in order if k in counts}


def _skipped_rules(scored: list[tuple[dict, Any]]) -> list[dict[str, Any]]:
    """Rules that could not be evaluated for want of data.

    Reported rather than silently ignored, because a rule that never fires looks
    identical to a rule that always passes.
    """
    by_rule: dict[str, dict[str, Any]] = {}
    for _record, result in scored:
        for entry in result.skipped:
            existing = by_rule.setdefault(entry["rule_id"], {
                "rule_id": entry["rule_id"],
                "title": entry["title"],
                "missing_fields": entry["missing_fields"],
                "endpoints": 0,
            })
            existing["endpoints"] += 1
    return sorted(by_rule.values(), key=lambda e: -e["endpoints"])
