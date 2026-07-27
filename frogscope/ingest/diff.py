"""Run-over-run change detection.

Structure adapted from frogy_web/ingest/diff.py — previous-run lookup, set diff
into added/removed/common, rows written to `changes`, a finding emitted per new
asset. Four departures, each fixing something that makes the original unusable
for this purpose:

1. **Field-level comparison.** The original detects "modified" only when the
   integer score changes, so a host losing its WAF at an identical score reports
   no change at all. Here every tracked field is compared with a comparator
   suited to its type.

2. **Prior rows are cleared before re-diffing.** The original never deletes, and
   `changes` has no unique constraint, so re-ingesting a run silently duplicates
   every change row.

3. **Noise is separated from signal.** Round-robin IPs, OAuth nonces, and render
   jitter all produce differences that mean nothing. Without handling them, every
   SSO endpoint in this dataset reports as changed on every run.

4. **Flapping is detected and demoted.** An asset that toggles in and out is
   unstable infrastructure or scan-scope churn. Left in the headline counts it
   makes the weekly summary cry wolf.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from dataclasses import field as dc_field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z")


# ── Value normalisation ─────────────────────────────────────────────────────

def normalise_url(value: Any, volatile: set[str]) -> str:
    """Strip per-request query parameters before comparing two URLs.

    Microsoft 365 redirects carry a fresh `nonce`, `state`, and
    `client-request-id` on every probe. Comparing raw, every federated login
    endpoint reports as changed every run — which is the single largest source of
    false change in this data.
    """
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        parts = urlsplit(text)
    except ValueError:
        return text
    if not parts.query:
        return text

    kept = [
        (k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)
        if k.lower() not in volatile
    ]
    kept.sort()
    return urlunsplit((parts.scheme, parts.netloc, parts.path,
                       urlencode(kept), ""))


def _as_set(value: Any) -> set[str]:
    if value is None:
        return set()
    if isinstance(value, (list, tuple, set)):
        return {str(v) for v in value if v not in (None, "")}
    if isinstance(value, str) and value.startswith("["):
        try:
            return {str(v) for v in json.loads(value) if v not in (None, "")}
        except json.JSONDecodeError:
            return {value}
    return {str(value)} if value != "" else set()


def _as_number(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    return str(value).strip().lower() in ("1", "true", "yes")


# ── Comparators ─────────────────────────────────────────────────────────────

@dataclass
class FieldChange:
    field: str
    before: Any
    after: Any
    severity: str
    direction: str = "lateral"
    added: list[str] = dc_field(default_factory=list)
    removed: list[str] = dc_field(default_factory=list)
    noisy: bool = False
    classification: bool = False
    summary: str = ""


def compare_field(name: str, spec: dict, before: Any, after: Any,
                  volatile: set[str]) -> FieldChange | None:
    """Compare one field. Returns None when the difference is not meaningful."""
    kind = spec.get("kind", "scalar")
    severity = spec.get("severity", "low")
    noisy = bool(spec.get("noisy"))

    if kind == "set":
        old, new = _as_set(before), _as_set(after)
        if old == new:
            return None
        gained, lost = sorted(new - old), sorted(old - new)
        bits = []
        if gained:
            bits.append(f"+{', '.join(gained[:5])}")
        if lost:
            bits.append(f"-{', '.join(lost[:5])}")
        return FieldChange(
            field=name, before=sorted(old), after=sorted(new), severity=severity,
            added=gained, removed=lost, noisy=noisy,
            direction="worse" if gained and not lost else
                      "better" if lost and not gained else "lateral",
            summary=f"{name}: {' '.join(bits)}",
        )

    if kind == "numeric":
        old, new = _as_number(before), _as_number(after)
        if old is None and new is None:
            return None
        if old is None or new is None:
            return FieldChange(field=name, before=before, after=after,
                               severity=severity, noisy=noisy,
                               summary=f"{name}: {before} → {after}")
        delta = abs(new - old)
        # Absorb jitter: a couple of bytes on a dynamic page is not a change.
        floor = float(spec.get("threshold", 0))
        pct = spec.get("threshold_pct")
        if pct is not None and old:
            floor = max(floor, abs(old) * float(pct) / 100.0)
        if delta <= floor:
            return None
        worse = spec.get("direction") == "up_is_worse"
        return FieldChange(
            field=name, before=old, after=new, severity=severity, noisy=noisy,
            direction=("worse" if (new > old) == worse else "better"),
            summary=f"{name}: {old:g} → {new:g}",
        )

    if kind == "ordinal":
        order = [str(o) for o in spec.get("order") or []]
        old, new = str(before or ""), str(after or "")
        if old == new:
            return None
        try:
            worse = order.index(new) > order.index(old)
        except ValueError:
            worse = None
        if spec.get("direction") == "up_is_worse" and worse is not None or worse is not None:
            direction = "worse" if worse else "better"
        else:
            direction = "lateral"
        return FieldChange(field=name, before=old, after=new, severity=severity,
                           direction=direction, noisy=noisy,
                           summary=f"{name}: {old or '(none)'} → {new or '(none)'}")

    if kind == "bool":
        old, new = _as_bool(before), _as_bool(after)
        if old == new:
            return None
        rule = spec.get("direction")
        if rule == "true_is_worse":
            direction = "worse" if new else "better"
        elif rule == "false_is_worse":
            direction = "better" if new else "worse"
        else:
            direction = "lateral"
        return FieldChange(field=name, before=old, after=new, severity=severity,
                           direction=direction, noisy=noisy,
                           summary=f"{name}: {'yes' if old else 'no'} → "
                                   f"{'yes' if new else 'no'}")

    if kind == "url":
        old = normalise_url(before, volatile)
        new = normalise_url(after, volatile)
        if old == new:
            return None
        return FieldChange(field=name, before=old, after=new, severity=severity,
                           noisy=noisy, summary=f"{name} changed")

    # scalar
    old, new = before, after
    if spec.get("normalise") == "whitespace":
        old = " ".join(str(old or "").split())
        new = " ".join(str(new or "").split())
    if str(old or "") == str(new or ""):
        return None
    return FieldChange(field=name, before=old, after=new, severity=severity,
                       noisy=noisy,
                       summary=f"{name}: {old or '(none)'} → {new or '(none)'}")


# ── Snapshot loading ────────────────────────────────────────────────────────

# Fields read straight off the endpoints row.
_LIST_FIELDS = {"a", "aaaa", "cname", "tech", "cpe_products", "wp_plugins"}


def load_snapshot(conn: sqlite3.Connection, run_id: int,
                  tracked: dict, classification: list[str]) -> dict[str, dict]:
    """Build {endpoint_key: {field: value}} for every tracked field."""
    wanted = set(tracked) | set(classification)
    columns = {
        r["name"] for r in conn.execute("PRAGMA table_info(endpoints)")
    }
    sources = {
        name: (spec.get("source") or name) for name, spec in tracked.items()
    }

    direct = sorted(
        {sources.get(f, f) for f in wanted}
        & columns | {"endpoint_key", "host", "lists_json"}
    )
    quoted = ",".join(f'"{c}"' for c in direct)

    findings_by_key: dict[str, set[str]] = {}
    for row in conn.execute(
        "SELECT endpoint_key, contributions_json FROM asset_scores "
        "WHERE run_id = ?", (run_id,)
    ):
        try:
            contributions = json.loads(row["contributions_json"] or "[]")
        except json.JSONDecodeError:
            continue
        findings_by_key[row["endpoint_key"]] = {
            c["rule_id"] for c in contributions
            if c.get("family") != "positive" and c.get("severity") != "info"
        }

    snapshot: dict[str, dict] = {}
    for row in conn.execute(
        f"SELECT {quoted} FROM endpoints WHERE run_id = ?", (run_id,)
    ):
        record = dict(row)
        lists_json = record.pop("lists_json", None)
        lists: dict[str, Any] = {}
        if lists_json:
            try:
                lists = json.loads(lists_json)
            except json.JSONDecodeError:
                lists = {}

        entry: dict[str, Any] = {"host": record.get("host")}
        for name in tracked:
            source = sources.get(name, name)
            if name in _LIST_FIELDS or source in _LIST_FIELDS:
                entry[name] = lists.get(source, [])
            elif source in record:
                entry[name] = record[source]
        for name in classification:
            if name in record:
                entry[name] = record[name]

        entry["findings"] = sorted(findings_by_key.get(row["endpoint_key"], set()))
        snapshot[row["endpoint_key"]] = entry

    return snapshot


# ── Presence and flapping ───────────────────────────────────────────────────

def update_presence(conn: sqlite3.Connection, project_id: int, run_id: int,
                    present: set[str], kind: str, window: int,
                    threshold: int, ordinal: int | None = None) -> None:
    """Append this run to every asset's presence string, then re-derive stability.

    Strings are aligned so character N always means run N. An asset first seen in
    run 3 is padded with leading zeros rather than starting at length 1 —
    otherwise position no longer corresponds to run, and flapping detection is
    silently wrong for every asset that was not present from the beginning.
    """
    known = {
        r["asset_key"]: dict(r) for r in conn.execute(
            "SELECT * FROM asset_presence WHERE project_id = ? AND asset_kind = ?",
            (project_id, kind))
    }
    if ordinal is None:
        ordinal = max(
            (len(r["presence"]) for r in known.values()), default=0) + 1

    for key in present | set(known):
        row = known.get(key)
        prior = row["presence"] if row else ""
        # Left-pad so every string is the same length before appending.
        prior = prior.rjust(ordinal - 1, "0")
        history = prior + ("1" if key in present else "0")
        # Bound the stored string so it cannot grow without limit; the window is
        # all that flapping detection needs.
        history = history[-max(window * 4, 32):]

        recent = history[-window:]
        flaps = sum(1 for a, b in zip(recent, recent[1:], strict=False) if a != b)
        absent_streak = len(history) - len(history.rstrip("0")) if history.endswith("0") else 0

        if key in present:
            stability = "new" if history.count("1") == 1 else (
                "intermittent" if flaps >= threshold else "stable")
        else:
            stability = "disappeared"

        conn.execute(
            """INSERT INTO asset_presence
                 (project_id, asset_kind, asset_key, presence, runs_seen,
                  runs_absent, absent_streak, flap_count, is_flapping, stability,
                  first_seen_run, last_seen_run)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(project_id, asset_kind, asset_key) DO UPDATE SET
                 presence = excluded.presence,
                 runs_seen = excluded.runs_seen,
                 runs_absent = excluded.runs_absent,
                 absent_streak = excluded.absent_streak,
                 flap_count = excluded.flap_count,
                 is_flapping = excluded.is_flapping,
                 stability = excluded.stability,
                 last_seen_run = COALESCE(excluded.last_seen_run,
                                          asset_presence.last_seen_run)""",
            (project_id, kind, key, history,
             history.count("1"), history.count("0"), absent_streak,
             flaps, 1 if flaps >= threshold else 0, stability,
             (row["first_seen_run"] if row else run_id) or run_id,
             run_id if key in present else (row["last_seen_run"] if row else None)),
        )


def flapping_keys(conn: sqlite3.Connection, project_id: int,
                  kind: str = "endpoint") -> set[str]:
    return {
        r["asset_key"] for r in conn.execute(
            "SELECT asset_key FROM asset_presence "
            "WHERE project_id = ? AND asset_kind = ? AND is_flapping = 1",
            (project_id, kind))
    }


# ── Attribute history ───────────────────────────────────────────────────────

def record_attr_history(conn: sqlite3.Connection, project_id: int, run_id: int,
                        key: str, changes: list[FieldChange]) -> None:
    """Sparse: a row only where a value actually changed."""
    stamp = _now()
    conn.executemany(
        """INSERT OR REPLACE INTO asset_attr_history
             (project_id, asset_kind, asset_key, field, run_id, value_json, changed_at)
           VALUES (?, 'endpoint', ?, ?, ?, ?, ?)""",
        [(project_id, key, c.field, run_id, json.dumps(c.after, default=str), stamp)
         for c in changes],
    )


# ── The diff ────────────────────────────────────────────────────────────────

def reset_presence(conn: sqlite3.Connection, project_id: int) -> None:
    """Clear presence history before replaying every run.

    `update_presence` appends one character per run. Replaying runs without
    clearing first appends a second time, so every asset looks as though it has
    been seen before — which turns genuinely new assets into "returned" and makes
    the added count read zero.
    """
    conn.execute("DELETE FROM asset_presence WHERE project_id = ?", (project_id,))


def diff_runs(conn: sqlite3.Connection, project_id: int, run_id: int,
              prev_run_id: int | None, cfg_diff: dict, *,
              persist: bool = True) -> dict[str, Any]:
    tracked: dict = cfg_diff.get("tracked") or {}
    classification: list[str] = cfg_diff.get("classification_fields") or []
    volatile = {p.lower() for p in cfg_diff.get("volatile_url_params") or []}
    window = int(cfg_diff.get("flap_window", 6))
    threshold = int(cfg_diff.get("flap_threshold", 3))

    current = load_snapshot(conn, run_id, tracked, classification)

    if persist:
        # Without this, re-ingesting or re-diffing a run duplicates every row.
        conn.execute("DELETE FROM changes WHERE run_id = ?", (run_id,))
        # The run's position in the chronological series, so presence strings
        # stay aligned across assets no matter when each was first seen.
        ordinal = conn.execute(
            "SELECT COUNT(*) n FROM runs WHERE project_id = ? "
            "AND duplicate_of IS NULL AND (COALESCE(started_at,'') , id) <= "
            "(SELECT COALESCE(started_at,''), id FROM runs WHERE id = ?)",
            (project_id, run_id),
        ).fetchone()["n"]
        update_presence(conn, project_id, run_id, set(current), "endpoint",
                        window, threshold, ordinal)
        update_presence(conn, project_id, run_id,
                        {r["host"] for r in current.values() if r.get("host")},
                        "host", window, threshold, ordinal)

    if prev_run_id is None:
        summary = {
            "baseline": True,
            "prev_run_id": None,
            "added": 0, "removed": 0, "modified": 0, "returned": 0,
            "unchanged": len(current),
            "worse": 0, "better": 0, "lateral": 0,
            "by_severity": {}, "by_field": {},
            "flapping": 0, "classification_changes": 0,
            "note": "First run for this project, so there is nothing to compare "
                    "against yet.",
        }
        if persist:
            conn.execute("UPDATE runs SET diff_json = ?, prev_run_id = NULL "
                         "WHERE id = ?", (json.dumps(summary), run_id))
        return summary

    previous = load_snapshot(conn, prev_run_id, tracked, classification)
    presence = {
        r["asset_key"]: dict(r) for r in conn.execute(
            "SELECT * FROM asset_presence WHERE project_id = ? AND asset_kind = "
            "'endpoint'", (project_id,))
    }
    flapping = {k for k, v in presence.items() if v["is_flapping"]}

    added_keys = set(current) - set(previous)
    removed_keys = set(previous) - set(current)
    common_keys = set(current) & set(previous)

    rows: list[tuple] = []
    stamp = _now()
    counts = {"added": 0, "removed": 0, "modified": 0, "returned": 0,
              "unchanged": 0}
    directions = {"worse": 0, "better": 0, "lateral": 0}
    by_severity: dict[str, int] = {}
    by_field: dict[str, int] = {}
    classification_changes = 0
    examples: dict[str, list[dict]] = {"added": [], "removed": [], "modified": []}

    def emit(kind: str, key: str, host: str | None, change: FieldChange | None,
             summary: str) -> None:
        rows.append((
            project_id, run_id, prev_run_id, "endpoint", key, host, kind,
            change.field if change else None,
            json.dumps(change.before, default=str) if change else None,
            json.dumps(change.after, default=str) if change else None,
            json.dumps(change.added) if change and change.added else None,
            json.dumps(change.removed) if change and change.removed else None,
            change.severity if change else "info",
            change.direction if change else None,
            1 if change and change.noisy else 0,
            1 if change and change.classification else 0,
            summary, stamp,
        ))

    for key in sorted(added_keys):
        entry = current[key]
        history = presence.get(key)
        # An asset that was seen before and vanished has not been "discovered";
        # calling it new every time it reappears destroys trust in the feed.
        returning = bool(history and history["presence"][:-1].count("1") > 0)
        kind = "returned" if returning else "added"
        counts[kind] += 1
        note = ("reappeared after being absent"
                if returning else "first seen in this run")
        emit(kind, key, entry.get("host"), None, f"{key} {note}")
        if len(examples["added" if not returning else "modified"]) < 20:
            examples["added" if not returning else "modified"].append({
                "asset_key": key, "host": entry.get("host"),
                "returning": returning,
                "flapping": key in flapping,
            })

    for key in sorted(removed_keys):
        entry = previous[key]
        history = presence.get(key)
        streak = history["absent_streak"] if history else 1
        transient = bool(history and history["flap_count"] > 0 and streak <= 1)
        counts["removed"] += 1
        emit("removed", key, entry.get("host"), None,
             f"{key} no longer responds"
             + (" (this asset has come and gone before)" if transient else ""))
        if len(examples["removed"]) < 20:
            examples["removed"].append({
                "asset_key": key, "host": entry.get("host"),
                "likely_transient": transient, "flapping": key in flapping,
            })

    for key in sorted(common_keys):
        old, new = previous[key], current[key]
        field_changes: list[FieldChange] = []

        for name, spec in tracked.items():
            change = compare_field(name, spec, old.get(name), new.get(name),
                                   volatile)
            if change:
                field_changes.append(change)

        for name in classification:
            change = compare_field(name, {"kind": "scalar", "severity": "info"},
                                   old.get(name), new.get(name), volatile)
            if change:
                change.classification = True
                change.summary = (
                    f"{name}: {change.before or '(none)'} → "
                    f"{change.after or '(none)'} (how frogscope classifies it, "
                    f"not a change to the asset)"
                )
                field_changes.append(change)
                classification_changes += 1

        if not field_changes:
            counts["unchanged"] += 1
            continue

        material = [c for c in field_changes
                    if not c.classification and not c.noisy]
        if material:
            counts["modified"] += 1
        else:
            # Only noise or reclassification changed. Recorded below so a
            # deliberate look can find it, but not counted as a modification —
            # otherwise a rotated IP reads the same as a lost WAF.
            counts["unchanged"] += 1

        for change in field_changes:
            # Rollups are built from material changes only. Counting noise here
            # is how "474 endpoints got worse" ends up meaning "8 IPs rotated".
            if not change.classification and not change.noisy:
                by_severity[change.severity] = by_severity.get(change.severity, 0) + 1
                by_field[change.field] = by_field.get(change.field, 0) + 1
                directions[change.direction] = directions.get(change.direction, 0) + 1
            emit("modified", key, new.get("host"), change, change.summary)

        if not material:
            continue

        if persist:
            record_attr_history(conn, project_id, run_id, key, material)

        if len(examples["modified"]) < 40:
            examples["modified"].append({
                "asset_key": key, "host": new.get("host"),
                "headline": headline_for(material),
                "worst_severity": min(
                    (c.severity for c in material),
                    key=lambda s: SEVERITY_RANK.get(s, 9), default="info"),
                "direction": _net_direction(material),
                "fields": [c.field for c in material],
            })

    if persist and rows:
        conn.executemany(
            """INSERT INTO changes
                 (project_id, run_id, prev_run_id, asset_kind, asset_key, host,
                  change_type, field, before_json, after_json, added_json,
                  removed_json, severity, direction, is_noisy,
                  is_classification, summary, created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            rows,
        )

    summary = {
        "baseline": False,
        "prev_run_id": prev_run_id,
        **counts,
        **{f"direction_{k}": v for k, v in directions.items()},
        "worse": directions["worse"],
        "better": directions["better"],
        "lateral": directions["lateral"],
        "by_severity": dict(sorted(
            by_severity.items(), key=lambda kv: SEVERITY_RANK.get(kv[0], 9))),
        "by_field": dict(sorted(by_field.items(), key=lambda kv: -kv[1])),
        "classification_changes": classification_changes,
        "flapping": len(flapping),
        # Flapping assets are excluded from the headline so the executive number
        # stays stable week to week.
        "added_excluding_flapping": sum(
            1 for e in examples["added"] if not e.get("flapping")),
        "examples": examples,
    }

    if persist:
        conn.execute("UPDATE runs SET diff_json = ?, prev_run_id = ? WHERE id = ?",
                     (json.dumps(summary, default=str), prev_run_id, run_id))

    return summary


def headline_for(changes: list[FieldChange]) -> str:
    """A single readable sentence for the most important change on an asset."""
    if not changes:
        return "changed"
    worst = min(changes, key=lambda c: (SEVERITY_RANK.get(c.severity, 9),
                                        0 if c.direction == "worse" else 1))

    phrases = {
        "waf_protected": ("WAF protection removed", "now WAF protected"),
        "origin_exposed": ("now reachable directly, with no proxy",
                           "no longer reachable directly"),
        "no_waf": ("no longer has a WAF in front", "now has a WAF in front"),
        "response_class": (None, None),
        "risk_band": (None, None),
    }
    pair = phrases.get(worst.field)
    if pair and pair[0]:
        return pair[0] if worst.direction == "worse" else pair[1]

    if worst.field == "findings":
        if worst.added:
            return f"new finding: {worst.added[0]}"
        if worst.removed:
            return f"resolved: {worst.removed[0]}"
    if worst.field == "response_class":
        return f"went from {worst.before} to {worst.after}"
    if worst.field == "risk_band":
        return f"risk moved {worst.before} → {worst.after}"
    if worst.field == "cname":
        return "DNS delegation changed"
    return worst.summary


def _net_direction(changes: list[FieldChange]) -> str:
    worse = sum(1 for c in changes if c.direction == "worse")
    better = sum(1 for c in changes if c.direction == "better")
    if worse > better:
        return "worse"
    if better > worse:
        return "better"
    return "lateral"


def previous_run_id(conn: sqlite3.Connection, project_id: int,
                    run_id: int) -> int | None:
    """The run immediately before this one *by scan time*.

    Ordered by when the scan happened rather than when it was ingested, so
    backfilling an older CSV slots into the timeline correctly.
    """
    rows = conn.execute(
        "SELECT id FROM runs WHERE project_id = ? AND duplicate_of IS NULL "
        "ORDER BY COALESCE(started_at,''), id", (project_id,),
    ).fetchall()
    ids = [r["id"] for r in rows]
    if run_id not in ids:
        return ids[-1] if ids else None
    index = ids.index(run_id)
    return ids[index - 1] if index > 0 else None
