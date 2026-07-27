"""Decide what is worth alerting on, and what has already been alerted.

No network here, on purpose. The judgement calls — is this finding new, is this
change real, has this already been sent — are the part that can be wrong in a
damaging way, so they live in a module that a test can drive with no webhook.

The bias throughout is toward silence. A channel that posts every week whether or
not anything happened gets muted, and then the one alert that mattered is missed
too. So:

* only findings whose FIRST sighting is this run,
* only score movement past a configured delta,
* nothing at all on a baseline run, where by definition everything is new,
* and a ledger, so re-running `notify` posts nothing a second time.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
_GRADE_RANK = {"high": 3, "medium": 2, "low": 1}
_ENV_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


class NotifyConfigError(RuntimeError):
    pass


# Explicit pairs rather than a suffix rule. A rule gave "10 worseneds", because
# the trigger name is an adjective and no amount of suffix logic fixes that.
_NOUNS = {
    "new_finding": ("new finding", "new findings"),
    "worsened": ("endpoint got worse", "endpoints got worse"),
    "takeover_candidate": ("takeover candidate", "takeover candidates"),
    "posture_drop": ("posture drop", "posture drops"),
    "data_quality": ("data quality warning", "data quality warnings"),
}


def _noun(trigger: str, count: int) -> str:
    singular, plural = _NOUNS.get(
        trigger, (trigger.replace("_", " "), trigger.replace("_", " ")))
    return singular if count == 1 else plural


@dataclass
class AlertItem:
    """One thing worth telling someone about."""
    trigger: str
    dedup_key: str
    severity: str
    headline: str
    detail: str = ""
    asset: str = ""
    url: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {"trigger": self.trigger, "dedup_key": self.dedup_key,
                "severity": self.severity, "headline": self.headline,
                "detail": self.detail, "asset": self.asset, "url": self.url}


@dataclass
class Alert:
    project: str
    run_key: str
    run_id: int
    project_id: int
    scanned_at: str = ""
    is_baseline: bool = False
    items: list[AlertItem] = field(default_factory=list)
    context: dict[str, Any] = field(default_factory=dict)
    suppressed: list[str] = field(default_factory=list)

    @property
    def worst(self) -> str:
        if not self.items:
            return "info"
        return max((i.severity for i in self.items),
                   key=lambda s: _SEVERITY_RANK.get(s, 0))

    def summary_line(self) -> str:
        if not self.items:
            return f"{self.project}: nothing new in {self.run_key}"
        counts: dict[str, int] = {}
        for item in self.items:
            counts[item.trigger] = counts.get(item.trigger, 0) + 1
        parts = [f"{count} {_noun(name, count)}"
                 for name, count in sorted(counts.items())]
        return f"{self.project}: " + ", ".join(parts)

    def as_dict(self) -> dict[str, Any]:
        return {
            "project": self.project, "run_key": self.run_key,
            "run_id": self.run_id, "scanned_at": self.scanned_at,
            "is_baseline": self.is_baseline,
            "summary": self.summary_line(), "worst_severity": self.worst,
            "item_count": len(self.items),
            "items": [i.as_dict() for i in self.items],
            "context": self.context,
            "suppressed": self.suppressed,
        }


# ── Config ──────────────────────────────────────────────────────────────────

def _expand(value: Any) -> Any:
    """Substitute ${VAR} from the environment.

    Config is committed to git, and a Slack webhook URL is a credential. An unset
    variable resolves to empty, and the caller reports that target as skipped —
    never posts to a half-expanded URL.
    """
    if isinstance(value, str):
        return _ENV_PATTERN.sub(lambda m: os.environ.get(m.group(1), ""), value)
    if isinstance(value, list):
        return [_expand(v) for v in value]
    if isinstance(value, dict):
        return {k: _expand(v) for k, v in value.items()}
    return value


def load_notify_config(config_dir: Path) -> dict[str, Any]:
    """Read `notify.yaml`.

    Loaded separately from the main config and NOT folded into `config_hash`.
    Where an alert is posted changes no derived value, so editing it must not
    make every stored run look as though its scoring inputs moved — that warning
    has to stay meaningful.
    """
    path = Path(config_dir) / "notify.yaml"
    if not path.exists():
        return {"enabled": False, "targets": [], "triggers": {}}
    try:
        loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise NotifyConfigError(f"{path} is not valid YAML: {exc}") from exc
    if not isinstance(loaded, dict):
        raise NotifyConfigError(f"{path} must be a mapping")
    return _expand(loaded)


def active_targets(notify_cfg: dict) -> tuple[list[dict], list[str]]:
    """Split targets into usable and skipped-with-a-reason.

    A target silently dropped for a missing environment variable is the failure
    mode where you believe alerting works and it does not.
    """
    usable, skipped = [], []
    for target in notify_cfg.get("targets") or []:
        name = target.get("name") or target.get("kind") or "unnamed"
        if not target.get("enabled"):
            skipped.append(f"{name}: disabled in notify.yaml")
            continue
        kind = target.get("kind")
        if kind == "file":
            if not target.get("path"):
                skipped.append(f"{name}: no path set")
                continue
        elif not target.get("url"):
            skipped.append(
                f"{name}: url is empty — the ${{VAR}} it references is unset")
            continue
        usable.append(target)
    return usable, skipped


def _trigger(notify_cfg: dict, name: str) -> dict:
    spec = (notify_cfg.get("triggers") or {}).get(name) or {}
    return spec if spec.get("enabled", True) else {}


# ── Building ────────────────────────────────────────────────────────────────

def build_alert(conn: sqlite3.Connection, run: sqlite3.Row,
                notify_cfg: dict, *, takeover_cfg: dict | None = None,
                include_sent: bool = False) -> Alert:
    """Assemble everything worth alerting on for one run."""
    project = conn.execute("SELECT slug, name FROM projects WHERE id = ?",
                           (run["project_id"],)).fetchone()
    alert = Alert(
        project=(project["name"] or project["slug"]) if project else "unknown",
        run_key=run["run_key"], run_id=run["id"], project_id=run["project_id"],
        scanned_at=run["completed_at"] or run["started_at"] or "",
        is_baseline=bool(run["is_baseline"]),
    )

    prior = conn.execute(
        "SELECT COUNT(*) AS n FROM runs WHERE project_id = ? AND id != ? "
        "AND COALESCE(duplicate_of, 0) = 0", (run["project_id"], run["id"])
    ).fetchone()["n"]
    alert.context = {
        "prior_runs": prior,
        "endpoints": run["endpoint_count"],
        "hosts": run["host_count"],
    }

    # A first run has no "new" — every finding is new, and posting all of them is
    # a wall of text nobody reads. Data-quality problems still go out, because a
    # broken baseline is worth knowing about immediately.
    baseline_only = prior == 0

    if not baseline_only:
        _new_findings(conn, run, notify_cfg, alert)
        _worsened(conn, run, notify_cfg, alert)
        _posture(conn, run, notify_cfg, alert)
    else:
        alert.suppressed.append(
            "first run for this project — new/changed triggers skipped, "
            "since a baseline makes everything look new")

    _takeover(conn, run, notify_cfg, alert, takeover_cfg or {})
    _data_quality(conn, run, notify_cfg, alert)

    if not include_sent:
        alert.items = [i for i in alert.items
                       if not _already_sent(conn, run["project_id"], i.dedup_key)]
    return alert


def _already_sent(conn: sqlite3.Connection, project_id: int,
                  dedup_key: str) -> bool:
    """True when this item went out to every target that wanted it.

    Checked per project across all targets here; `sinks.record` enforces it per
    target, so adding a channel later does not start it silent.
    """
    row = conn.execute(
        "SELECT 1 FROM notifications WHERE project_id = ? AND dedup_key = ? "
        "AND status = 'sent' LIMIT 1", (project_id, dedup_key)).fetchone()
    return row is not None


def _new_findings(conn, run, notify_cfg, alert: Alert) -> None:
    spec = _trigger(notify_cfg, "new_findings")
    if not spec:
        return
    floor = _SEVERITY_RANK.get(str(spec.get("min_severity", "high")), 3)
    limit = int(spec.get("max_listed", 15))

    rows = conn.execute(
        """SELECT rule_id, severity, confidence, title, asset_key, detail_json
             FROM findings
            WHERE project_id = ? AND first_seen_run_id = ? AND status = 'open'
            ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                                   WHEN 'medium' THEN 2 WHEN 'low' THEN 3
                                   ELSE 4 END, rule_id, asset_key""",
        (run["project_id"], run["id"])).fetchall()

    eligible = [r for r in rows
                if _SEVERITY_RANK.get(r["severity"], 0) >= floor]
    for row in eligible[:limit]:
        detail = {}
        if row["detail_json"]:
            try:
                detail = json.loads(row["detail_json"]) or {}
            except (TypeError, ValueError):
                detail = {}
        alert.items.append(AlertItem(
            trigger="new_finding",
            # Keyed on the finding, not the run: the same issue reappearing in a
            # later run must not re-page.
            dedup_key=f"finding:{row['rule_id']}:{row['asset_key']}",
            severity=row["severity"],
            headline=f"{row['title']} on {row['asset_key']}",
            detail=str(detail.get("why") or detail.get("remediation") or "")[:400],
            asset=row["asset_key"],
        ))
    if len(eligible) > limit:
        alert.suppressed.append(
            f"{len(eligible) - limit} further new findings not listed "
            f"(max_listed = {limit}) — see the Findings tab")


def _worsened(conn, run, notify_cfg, alert: Alert) -> None:
    spec = _trigger(notify_cfg, "worsened")
    if not spec:
        return
    threshold = float(spec.get("min_score_delta", 15))
    limit = int(spec.get("max_listed", 10))
    eligible = 0

    for row in conn.execute(
        """SELECT asset_key, host, change_type, field, before_json, after_json,
                  severity, summary
             FROM changes
            WHERE run_id = ? AND direction = 'worse' AND is_noisy = 0
              AND is_classification = 0
            ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                                   WHEN 'medium' THEN 2 ELSE 3 END,
                     asset_key""", (run["id"],)
    ):
        # A classification change is a config edit of ours, not attacker
        # activity, and noisy fields are excluded for the same reason they are
        # excluded from the change rollups.
        delta = _score_move(row)
        if _SEVERITY_RANK.get(row["severity"], 0) < 3 and delta < threshold:
            continue
        eligible += 1
        if eligible > limit:
            continue
        asset = row["asset_key"] or row["host"] or ""
        summary = row["summary"] or "got worse"
        # The change summary is written for a table that already has an asset
        # column, so on its own it reads "response_class: waf_blocked →
        # live_content" with no clue which host. An alert nobody can act on
        # without opening the dashboard is not worth sending.
        headline = summary if asset and asset in summary \
            else f"{asset}: {summary}" if asset else summary
        alert.items.append(AlertItem(
            trigger="worsened",
            # Includes the run: unlike a finding, a change belongs to the
            # transition, and the same host worsening again next month is news.
            dedup_key=f"worse:{run['id']}:{row['asset_key']}:{row['field'] or ''}",
            severity=row["severity"] if row["severity"] in _SEVERITY_RANK
                     else "medium",
            headline=headline,
            detail=(f"{row['field']}: {row['before_json']} → {row['after_json']}"
                    if row["field"] else ""),
            asset=asset,
        ))

    if eligible > limit:
        alert.suppressed.append(
            f"{eligible - limit} further worsened endpoints not listed "
            f"(max_listed = {limit}) — see the Changes tab")


def _score_move(row: sqlite3.Row) -> float:
    """How far the score moved, when this change is a score change at all."""
    if row["field"] not in ("risk_score", "score"):
        return 0.0
    try:
        return abs(float(json.loads(row["after_json"]))
                   - float(json.loads(row["before_json"])))
    except (TypeError, ValueError):
        return 0.0


def _takeover(conn, run, notify_cfg, alert: Alert, takeover_cfg: dict) -> None:
    spec = _trigger(notify_cfg, "takeover")
    if not spec:
        return
    floor = _GRADE_RANK.get(str(spec.get("min_grade", "medium")), 2)
    limit = int(spec.get("max_listed", 20))
    eligible = 0

    for row in conn.execute(
        """SELECT DISTINCT host, takeover_grade, takeover_provider,
                  cname_final, origin_health
             FROM endpoints
            WHERE run_id = ? AND takeover_grade != ''""", (run["id"],)
    ):
        if _GRADE_RANK.get(row["takeover_grade"], 0) < floor:
            continue
        eligible += 1
        if eligible > limit:
            continue
        alert.items.append(AlertItem(
            trigger="takeover_candidate",
            dedup_key=f"takeover:{row['host']}:{row['takeover_grade']}",
            severity="critical" if row["takeover_grade"] == "high" else "high",
            headline=f"Possible dangling record: {row['host']}",
            # Wording matters: nothing here is confirmed, and an alert that
            # overclaims gets the whole channel distrusted.
            detail=(f"Provider {row['takeover_provider'] or 'unknown'}, "
                    f"CNAME {row['cname_final'] or 'none'}, origin "
                    f"{row['origin_health'] or 'unknown'}. Candidate only — "
                    f"run `frogscope verify --takeover` to confirm."),
            asset=row["host"],
        ))

    if eligible > limit:
        alert.suppressed.append(
            f"{eligible - limit} further takeover candidates not listed "
            f"(max_listed = {limit}) — see the Takeover tab")


def _posture(conn, run, notify_cfg, alert: Alert) -> None:
    spec = _trigger(notify_cfg, "posture_drop")
    if not spec:
        return
    drop = float(spec.get("min_points", 3))

    series = conn.execute(
        """SELECT m.run_id, m.value
             FROM run_metrics m JOIN runs r ON r.id = m.run_id
            WHERE r.project_id = ? AND m.metric = 'posture_index_host'
              AND m.dim = 'all' AND COALESCE(r.duplicate_of, 0) = 0
            ORDER BY COALESCE(r.started_at, ''), r.id""",
        (run["project_id"],)).fetchall()
    current = next((r for r in series if r["run_id"] == run["id"]), None)
    if current is None:
        return
    index = series.index(current)
    if index == 0:
        return
    previous = series[index - 1]
    delta = current["value"] - previous["value"]
    if delta > -drop:
        return
    alert.items.append(AlertItem(
        trigger="posture_drop",
        dedup_key=f"posture:{run['id']}",
        severity="high",
        headline=(f"Posture index fell {abs(delta):.1f} points to "
                  f"{current['value']:.1f}"),
        # Host-weighted, and said so: the endpoint-weighted number reads far
        # healthier because Cloudflare alias ports outnumber real services.
        detail="Host-weighted index. Every host counts once, however many "
               "ports it exposes.",
    ))


def _data_quality(conn, run, notify_cfg, alert: Alert) -> None:
    spec = _trigger(notify_cfg, "data_quality")
    if not spec:
        return

    problems: list[str] = []
    if run["incomplete"]:
        problems.append("the scan looks unfinished and was accepted anyway")
    try:
        warnings = json.loads(run["warnings_json"] or "[]") or []
    except (TypeError, ValueError):
        warnings = []
    problems.extend(str(w) for w in warnings[:5])

    if not run["endpoint_count"]:
        problems.append("the run contains no endpoints at all")

    if not problems:
        return
    alert.items.append(AlertItem(
        trigger="data_quality",
        dedup_key=f"quality:{run['id']}",
        severity="medium",
        # A truncated scan is the dangerous case: fewer findings reads as an
        # improvement, so it has to be said out loud.
        headline=f"Data quality warnings on {run['run_key']}",
        detail="; ".join(problems)[:600],
    ))
