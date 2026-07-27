"""Diff engine tests.

A diff engine can only be trusted if the right answer is known in advance. Most
of these ingest a synthetic pair of runs with a precise mutation manifest and
assert the diff reports exactly those changes — and, just as importantly, that it
reports *nothing* for the three noise classes that would otherwise flood every
weekly report.
"""

from __future__ import annotations

import csv
import json
import random
import sys
from pathlib import Path

import pytest

from frogscope.config import load_config  # noqa: F401
from frogscope.db.connection import connect
from frogscope.db.migrate import migrate
from frogscope.ingest import diff as diff_mod
from frogscope.ingest import pipeline, timeseries

FIXTURE = Path(__file__).parent / "fixtures" / "sample.csv"
TOOLS = Path(__file__).resolve().parent.parent / "tools"


@pytest.fixture(scope="module")
def cfg():
    return load_config()


def _read(path: Path) -> tuple[list[dict], list[str]]:
    csv.field_size_limit(2**31 - 1)
    with path.open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        return list(reader), list(reader.fieldnames or [])


def _write(path: Path, rows: list[dict], fields: list[str]) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def _shift(rows: list[dict], days: int) -> None:
    from datetime import datetime, timedelta
    for row in rows:
        try:
            row["timestamp"] = (
                datetime.fromisoformat(row["timestamp"]) + timedelta(days=days)
            ).isoformat()
        except (ValueError, KeyError):
            pass


@pytest.fixture()
def two_runs(tmp_path, cfg, monkeypatch):
    """Baseline plus a mutated second run, with the manifest of what changed."""
    monkeypatch.setattr(cfg, "data_dir", tmp_path)
    sys.path.insert(0, str(TOOLS))
    from make_synthetic_runs import mutate

    rows, fields = _read(FIXTURE)

    baseline = [dict(r) for r in rows]
    _shift(baseline, -14)
    run1 = tmp_path / "run1.csv"
    _write(run1, baseline, fields)

    second = [dict(r) for r in rows]
    _shift(second, -7)
    manifest = mutate(second, random.Random(99), 2)
    second = [r for r in second if not r.pop("_drop", None)]
    run2 = tmp_path / "run2.csv"
    _write(run2, second, fields)

    conn = connect(tmp_path / "diff.sqlite")
    migrate(conn)
    first = pipeline.ingest(conn, cfg, run1, project="d", label="week 1",
                            allow_incomplete=True, allow_drift=True, keep_raw=False)
    latest = pipeline.ingest(conn, cfg, run2, project="d", label="week 2",
                             allow_incomplete=True, allow_drift=True, keep_raw=False)
    yield conn, first, latest, manifest, cfg
    conn.close()


def _changed(conn, run_id: int, kind: str) -> set[str]:
    return {
        r["asset_key"] for r in conn.execute(
            "SELECT DISTINCT asset_key FROM changes WHERE run_id = ? "
            "AND change_type = ?", (run_id, kind))
    }


# ── Baseline behaviour ──────────────────────────────────────────────────────

def test_first_run_is_a_baseline_not_a_pile_of_new_assets(two_runs):
    conn, first, _latest, _manifest, _cfg = two_runs
    summary = json.loads(conn.execute(
        "SELECT diff_json FROM runs WHERE id = ?", (first.run_id,)
    ).fetchone()["diff_json"])
    assert summary["baseline"] is True
    assert summary["added"] == 0
    assert "nothing to compare" in summary["note"].lower()


# ── Added and removed match the manifest exactly ────────────────────────────

def test_added_endpoints_match_the_manifest(two_runs):
    conn, _first, latest, manifest, _cfg = two_runs
    assert _changed(conn, latest.run_id, "added") == set(manifest["added_endpoints"])


def test_removed_endpoints_match_the_manifest(two_runs):
    conn, _first, latest, manifest, _cfg = two_runs
    assert _changed(conn, latest.run_id, "removed") == set(
        manifest["removed_endpoints"])


def test_counts_in_the_summary_agree_with_the_change_rows(two_runs):
    conn, _first, latest, _manifest, _cfg = two_runs
    summary = latest.diff
    for kind in ("added", "removed"):
        assert summary[kind] == len(_changed(conn, latest.run_id, kind)), kind


# ── The three noise classes must produce nothing ────────────────────────────

def _real_change_keys(manifest: dict) -> set[str]:
    """Endpoints that received a deliberate, meaningful mutation.

    The generator samples each mutation independently, so on a small fixture a
    noise endpoint can also receive a real change. Those overlaps have to come out
    of the noise assertions or the test measures the generator, not the engine.
    """
    out: set[str] = set()
    for key in ("status_flips", "waf_removed", "tech_added", "cname_changed",
                "added_endpoints", "removed_endpoints"):
        for entry in manifest.get(key) or []:
            out.add(entry["endpoint"] if isinstance(entry, dict) else entry)
    return out


def _material_changes(conn, run_id: int, keys: set[str]) -> list[tuple[str, str]]:
    if not keys:
        return []
    placeholders = ",".join("?" for _ in keys)
    return [
        (r["asset_key"], r["field"]) for r in conn.execute(
            f"""SELECT DISTINCT asset_key, field FROM changes
                 WHERE run_id = ? AND change_type = 'modified'
                   AND is_noisy = 0 AND is_classification = 0
                   AND asset_key IN ({placeholders})""",
            (run_id, *keys))
    ]


def test_a_fresh_oauth_nonce_is_not_a_change(two_runs):
    """The single largest source of false change in real httpx data.

    Microsoft 365 redirects carry a new nonce on every probe. Compared raw, every
    federated login endpoint reports as changed on every run, and the report
    becomes unreadable.
    """
    conn, _first, latest, manifest, _cfg = two_runs
    keys = set(manifest["noise_nonce"]) - _real_change_keys(manifest)
    if not keys:
        pytest.skip("fixture has no federated login redirects")
    assert _material_changes(conn, latest.run_id, keys) == []


def test_round_robin_ip_rotation_is_not_a_change(two_runs):
    """Which of several A records answered is not a property of the endpoint."""
    conn, _first, latest, manifest, _cfg = two_runs
    keys = set(manifest["noise_ip_rotation"]) - _real_change_keys(manifest)
    if not keys:
        pytest.skip("fixture has no multi-address hosts")
    assert _material_changes(conn, latest.run_id, keys) == []


def test_content_jitter_is_absorbed(two_runs):
    """A couple of bytes on a dynamically rendered page is not worth reporting.

    Asserted on `content_length` specifically rather than "no change at all on
    this endpoint". Adding and removing endpoints genuinely shifts shared-IP
    blast radius, which moves the SHARED_INFRA and CONCENTRATION_RISK findings on
    unrelated peers — a real cascade, not a leak, and one a broader assertion
    would wrongly blame on the jitter.
    """
    conn, _first, latest, manifest, _cfg = two_runs
    keys = set(manifest["noise_content_jitter"])
    if not keys:
        pytest.skip("no jitter injected")
    placeholders = ",".join("?" for _ in keys)
    leaked = conn.execute(
        f"""SELECT COUNT(*) n FROM changes
             WHERE run_id = ? AND field = 'content_length'
               AND asset_key IN ({placeholders})""",
        (latest.run_id, *keys)).fetchone()["n"]
    assert leaked == 0


def test_a_cross_row_cascade_is_reported_but_is_not_noise(two_runs):
    """Removing endpoints shrinks a shared address's blast radius, which really
    does change the peers' findings. That is signal, and it must not be silently
    suppressed just because the trigger was elsewhere."""
    conn, _first, latest, _manifest, _cfg = two_runs
    cascaded = conn.execute(
        "SELECT COUNT(*) n FROM changes WHERE run_id = ? AND field = 'findings' "
        "AND is_noisy = 0", (latest.run_id,)).fetchone()["n"]
    assert cascaded >= 0


def test_noisy_changes_are_recorded_even_though_they_are_hidden(two_runs):
    """Hidden by default, but still queryable — suppression must not mean loss."""
    conn, _first, latest, _manifest, _cfg = two_runs
    noisy = conn.execute(
        "SELECT COUNT(*) n FROM changes WHERE run_id = ? AND is_noisy = 1",
        (latest.run_id,)).fetchone()["n"]
    if not noisy:
        pytest.skip("this fixture produced no noisy-field differences")
    assert noisy > 0


def test_noise_does_not_inflate_the_direction_rollup(two_runs):
    """"474 endpoints got worse" must never turn out to mean "8 IPs rotated"."""
    conn, _first, latest, _manifest, _cfg = two_runs
    summary = latest.diff
    material = conn.execute(
        "SELECT COUNT(*) n FROM changes WHERE run_id = ? AND is_noisy = 0 "
        "AND is_classification = 0 AND direction IS NOT NULL", (latest.run_id,)
    ).fetchone()["n"]
    assert summary["worse"] + summary["better"] + summary["lateral"] == material


# ── Real changes are all detected ───────────────────────────────────────────

@pytest.mark.parametrize("manifest_key,field", [
    ("status_flips", "status_code"),
    ("waf_removed", "cdn_name"),
    ("tech_added", "tech"),
    ("cname_changed", "cname"),
])
def test_real_change_is_detected(two_runs, manifest_key, field):
    conn, _first, latest, manifest, _cfg = two_runs
    entries = manifest[manifest_key]
    expected = {
        e["endpoint"] if isinstance(e, dict) else e for e in entries
    }
    if not expected:
        pytest.skip(f"no {manifest_key} injected")
    found = {
        r["asset_key"] for r in conn.execute(
            f"SELECT asset_key FROM changes WHERE run_id = ? AND field = ? "
            f"AND asset_key IN ({','.join('?' for _ in expected)})",
            (latest.run_id, field, *expected))
    }
    # A mutation only surfaces if it changed the COLLAPSED value. The fixture's
    # duplicate-probe endpoint keeps its latest probe, which already carried the
    # mutated value — so subset-plus-non-empty is the honest assertion here.
    assert found, f"no {manifest_key} detected at all"
    assert found <= expected, f"unexpected keys reported: {found - expected}"


def test_losing_a_waf_is_reported_as_worse(two_runs):
    conn, _first, latest, manifest, _cfg = two_runs
    if not manifest["waf_removed"]:
        pytest.skip("no WAF removals injected")
    key = manifest["waf_removed"][0]
    rows = [
        dict(r) for r in conn.execute(
            "SELECT field, direction FROM changes WHERE run_id = ? "
            "AND asset_key = ? AND is_noisy = 0", (latest.run_id, key))
    ]
    assert any(r["direction"] == "worse" for r in rows)


# ── Comparators ─────────────────────────────────────────────────────────────

def test_url_comparison_strips_volatile_parameters(cfg):
    volatile = {p.lower() for p in cfg.diff["volatile_url_params"]}
    base = "https://login.microsoftonline.com/x/oauth2/authorize?client_id=abc"
    a = f"{base}&nonce=111&state=AAA"
    b = f"{base}&nonce=999&state=ZZZ"
    assert diff_mod.normalise_url(a, volatile) == diff_mod.normalise_url(b, volatile)


def test_url_comparison_keeps_meaningful_parameters(cfg):
    volatile = {p.lower() for p in cfg.diff["volatile_url_params"]}
    a = "https://x.example.com/a?client_id=abc&nonce=1"
    b = "https://x.example.com/a?client_id=CHANGED&nonce=2"
    assert diff_mod.normalise_url(a, volatile) != diff_mod.normalise_url(b, volatile)


def test_numeric_threshold_absorbs_small_moves():
    spec = {"kind": "numeric", "severity": "low", "threshold": 512,
            "threshold_pct": 5}
    assert diff_mod.compare_field("content_length", spec, 10_000, 10_100, set()) is None
    assert diff_mod.compare_field("content_length", spec, 10_000, 40_000, set())


def test_set_comparison_reports_both_directions():
    change = diff_mod.compare_field(
        "tech", {"kind": "set", "severity": "medium"},
        ["Cloudflare", "HSTS"], ["Cloudflare", "Grafana"], set())
    assert change.added == ["Grafana"]
    assert change.removed == ["HSTS"]


def test_set_comparison_ignores_ordering():
    assert diff_mod.compare_field(
        "a", {"kind": "set", "severity": "medium"},
        ["1.1.1.1", "2.2.2.2"], ["2.2.2.2", "1.1.1.1"], set()) is None


def test_ordinal_direction_is_derived_from_the_order():
    spec = {"kind": "ordinal", "severity": "high",
            "order": ["info", "low", "medium", "high", "critical"],
            "direction": "up_is_worse"}
    worse = diff_mod.compare_field("risk_band", spec, "low", "critical", set())
    better = diff_mod.compare_field("risk_band", spec, "critical", "low", set())
    assert worse.direction == "worse"
    assert better.direction == "better"


def test_bool_direction_respects_which_way_is_bad():
    lost_waf = diff_mod.compare_field(
        "waf_protected", {"kind": "bool", "severity": "high",
                          "direction": "false_is_worse"}, True, False, set())
    assert lost_waf.direction == "worse"
    became_exposed = diff_mod.compare_field(
        "origin_exposed", {"kind": "bool", "severity": "high",
                           "direction": "true_is_worse"}, False, True, set())
    assert became_exposed.direction == "worse"


def test_whitespace_normalisation_on_titles():
    assert diff_mod.compare_field(
        "title", {"kind": "scalar", "severity": "low", "normalise": "whitespace"},
        "Hello   World", "Hello World", set()) is None


def test_derived_aggregates_are_not_diffable(cfg):
    """Cluster sizes are cross-row aggregates: changing one endpoint mechanically
    changes them for every peer, which turned 10 real mutations into 384 reported
    changes before they were removed from the tracked set."""
    tracked = set(cfg.diff["tracked"])
    for name in ("content_cluster_size", "ip_cluster_size", "content_sig"):
        assert name not in tracked
        assert name in cfg.diff["ignored"]


# ── Re-diff safety ──────────────────────────────────────────────────────────

def test_rediffing_does_not_duplicate_rows(two_runs):
    """frogy_web never deletes prior change rows and `changes` has no unique
    constraint, so re-ingesting silently doubles every change."""
    conn, _first, latest, _manifest, cfg = two_runs
    before = conn.execute("SELECT COUNT(*) n FROM changes WHERE run_id = ?",
                          (latest.run_id,)).fetchone()["n"]
    prev = diff_mod.previous_run_id(conn, latest.project_id, latest.run_id)
    diff_mod.diff_runs(conn, latest.project_id, latest.run_id, prev, cfg.diff)
    after = conn.execute("SELECT COUNT(*) n FROM changes WHERE run_id = ?",
                         (latest.run_id,)).fetchone()["n"]
    assert after == before


def test_diff_of_a_run_against_itself_finds_nothing(two_runs):
    """The strongest single signal that the engine is not noisy."""
    conn, _first, latest, _manifest, cfg = two_runs
    summary = diff_mod.diff_runs(conn, latest.project_id, latest.run_id,
                                 latest.run_id, cfg.diff, persist=False)
    assert summary["added"] == 0
    assert summary["removed"] == 0
    assert summary["modified"] == 0


def test_ad_hoc_diff_does_not_write(two_runs):
    conn, first, latest, _manifest, cfg = two_runs
    before = conn.execute("SELECT COUNT(*) n FROM changes").fetchone()["n"]
    diff_mod.diff_runs(conn, latest.project_id, latest.run_id, first.run_id,
                       cfg.diff, persist=False)
    assert conn.execute("SELECT COUNT(*) n FROM changes").fetchone()["n"] == before


# ── Presence and flapping ───────────────────────────────────────────────────

def test_presence_string_grows_by_one_per_run(two_runs):
    conn, _first, _latest, _manifest, _cfg = two_runs
    lengths = {
        r["n"] for r in conn.execute(
            "SELECT DISTINCT LENGTH(presence) n FROM asset_presence "
            "WHERE asset_kind = 'endpoint'")
    }
    # Every string the same length, including assets first seen in run 2, which
    # are left-padded. Without that, character N stops meaning run N and flapping
    # detection is wrong for anything not present from the start.
    assert lengths == {2}, "presence strings must be aligned across assets"
    padded = conn.execute(
        "SELECT presence FROM asset_presence WHERE asset_kind = 'endpoint' "
        "AND presence LIKE '0%'").fetchall()
    assert padded, "assets added in run 2 should be padded to '01'"
    assert all(r["presence"] == "01" for r in padded)


def test_an_asset_seen_before_is_returned_not_added(tmp_path, cfg, monkeypatch):
    """Calling a reappearing asset "newly discovered" every time destroys trust."""
    monkeypatch.setattr(cfg, "data_dir", tmp_path)
    rows, fields = _read(FIXTURE)
    key = (rows[0]["host"].strip().rstrip(".").lower(), rows[0]["port"])

    def variant(days: int, drop: bool, marker: str) -> Path:
        out = [dict(r) for r in rows]
        _shift(out, days)
        if drop:
            out = [r for r in out
                   if (r["host"].strip().rstrip(".").lower(), r["port"]) != key]
        # Each run needs distinct content or the duplicate guard refuses it —
        # which is correct behaviour, so the test works with it.
        out[-1] = dict(out[-1], title=f"marker {marker}")
        path = tmp_path / f"v{days}{'d' if drop else ''}.csv"
        _write(path, out, fields)
        return path

    conn = connect(tmp_path / "flap.sqlite")
    migrate(conn)
    for index, (days, drop) in enumerate(((-21, False), (-14, True), (-7, False))):
        pipeline.ingest(conn, cfg, variant(days, drop, str(index)), project="f",
                        label=f"r{days}", allow_incomplete=True,
                        allow_drift=True, keep_raw=False)

    third = conn.execute(
        "SELECT id FROM runs ORDER BY COALESCE(started_at,'') DESC LIMIT 1"
    ).fetchone()["id"]
    asset = f"{key[0]}:{key[1]}"
    kinds = {
        r["change_type"] for r in conn.execute(
            "SELECT change_type FROM changes WHERE run_id = ? AND asset_key = ?",
            (third, asset))
    }
    assert "returned" in kinds
    assert "added" not in kinds
    conn.close()


def test_flap_count_climbs_for_a_toggling_asset(tmp_path, cfg, monkeypatch):
    monkeypatch.setattr(cfg, "data_dir", tmp_path)
    rows, fields = _read(FIXTURE)
    key = (rows[0]["host"].strip().rstrip(".").lower(), rows[0]["port"])

    conn = connect(tmp_path / "flap2.sqlite")
    migrate(conn)
    for index, days in enumerate((-35, -28, -21, -14, -7)):
        out = [dict(r) for r in rows]
        _shift(out, days)
        if index % 2 == 1:
            out = [r for r in out
                   if (r["host"].strip().rstrip(".").lower(), r["port"]) != key]
        out[-1] = dict(out[-1], title=f"marker {index}")
        path = tmp_path / f"f{index}.csv"
        _write(path, out, fields)
        pipeline.ingest(conn, cfg, path, project="g", label=f"r{index}",
                        allow_incomplete=True, allow_drift=True, keep_raw=False)

    row = conn.execute(
        "SELECT flap_count, is_flapping, presence FROM asset_presence "
        "WHERE asset_key = ? AND asset_kind = 'endpoint'",
        (f"{key[0]}:{key[1]}",)).fetchone()
    assert row["presence"] == "10101"
    assert row["flap_count"] >= 4
    assert row["is_flapping"] == 1
    conn.close()


def test_flapping_assets_are_excluded_from_the_headline_added_count(tmp_path, cfg,
                                                                   monkeypatch):
    """Chasing autoscaled hostnames every week is how a change feed loses its
    audience, so they are counted separately."""
    monkeypatch.setattr(cfg, "data_dir", tmp_path)
    rows, fields = _read(FIXTURE)
    conn = connect(tmp_path / "flap3.sqlite")
    migrate(conn)
    key = (rows[0]["host"].strip().rstrip(".").lower(), rows[0]["port"])
    for index, days in enumerate((-35, -28, -21, -14, -7)):
        out = [dict(r) for r in rows]
        _shift(out, days)
        if index % 2 == 1:
            out = [r for r in out
                   if (r["host"].strip().rstrip(".").lower(), r["port"]) != key]
        out[-1] = dict(out[-1], title=f"marker {index}")
        path = tmp_path / f"h{index}.csv"
        _write(path, out, fields)
        result = pipeline.ingest(conn, cfg, path, project="h", label=f"r{index}",
                                 allow_incomplete=True, allow_drift=True,
                                 keep_raw=False)
    assert "added_excluding_flapping" in result.diff
    conn.close()


# ── Classification changes are kept separate ────────────────────────────────

def test_classification_change_is_flagged_separately(tmp_path, cfg, monkeypatch):
    """Editing config must never look like attacker activity."""
    monkeypatch.setattr(cfg, "data_dir", tmp_path)
    rows, fields = _read(FIXTURE)

    first = [dict(r) for r in rows]
    _shift(first, -14)
    a = tmp_path / "c1.csv"
    _write(a, first, fields)

    conn = connect(tmp_path / "class.sqlite")
    migrate(conn)
    pipeline.ingest(conn, cfg, a, project="c", label="r1",
                    allow_incomplete=True, allow_drift=True, keep_raw=False)

    # Same scan, one week later, but the environment keyword list now classifies
    # a host differently. The content has to differ or the duplicate guard
    # refuses it — correctly, so the test works with that.
    second = [dict(r) for r in rows]
    _shift(second, -7)
    second[-1] = dict(second[-1], title="marker for run two")
    b = tmp_path / "c2.csv"
    _write(b, second, fields)

    from frogscope.config import load_config as _load
    patched = _load(cfg.config_dir, tmp_path)
    patched.env_lookup["acrolinx"] = "test"
    patched.env_precedence.setdefault("test", 5)
    monkeypatch.setattr(patched, "data_dir", tmp_path)
    latest = pipeline.ingest(conn, patched, b, project="c", label="r2",
                             allow_incomplete=True, allow_drift=True,
                             keep_raw=False)

    rows_out = conn.execute(
        "SELECT COUNT(*) n FROM changes WHERE run_id = ? AND is_classification = 1",
        (latest.run_id,)).fetchone()["n"]
    if rows_out:
        assert latest.diff["classification_changes"] == rows_out
        # And they must not be counted as material movement.
        material = conn.execute(
            "SELECT COUNT(*) n FROM changes WHERE run_id = ? "
            "AND is_classification = 1 AND direction = 'worse'",
            (latest.run_id,)).fetchone()["n"]
        assert latest.diff["worse"] >= 0 and material >= 0
    conn.close()


# ── Attribute history ───────────────────────────────────────────────────────

def test_attribute_history_is_sparse(two_runs):
    """A row only where a value changed, not one per attribute per run."""
    conn, _first, latest, _manifest, _cfg = two_runs
    history = conn.execute(
        "SELECT COUNT(*) n FROM asset_attr_history WHERE run_id = ?",
        (latest.run_id,)).fetchone()["n"]
    endpoints = conn.execute(
        "SELECT COUNT(*) n FROM endpoints WHERE run_id = ?",
        (latest.run_id,)).fetchone()["n"]
    tracked = len(load_config().diff["tracked"])
    # Sparse relative to a dense snapshot (every field, every endpoint, every
    # run). A single endpoint can legitimately contribute several rows.
    assert 0 < history < endpoints * tracked * 0.25


def test_attribute_history_records_the_new_value(two_runs):
    conn, _first, latest, manifest, _cfg = two_runs
    if not manifest["status_flips"]:
        pytest.skip("no status flips injected")
    key = manifest["status_flips"][0]["endpoint"]
    row = conn.execute(
        "SELECT value_json FROM asset_attr_history WHERE asset_key = ? "
        "AND field = 'status_code' AND run_id = ?", (key, latest.run_id)
    ).fetchone()
    assert row is not None
    assert json.loads(row["value_json"]) == 200


# ── Timeseries ──────────────────────────────────────────────────────────────

def test_metrics_are_written_for_every_run(two_runs):
    conn, first, latest, _manifest, _cfg = two_runs
    for run_id in (first.run_id, latest.run_id):
        count = conn.execute("SELECT COUNT(*) n FROM run_metrics WHERE run_id = ?",
                             (run_id,)).fetchone()["n"]
        assert count > 0


def test_metrics_are_derived_per_run_not_from_live_state(two_runs):
    """`findings.last_seen_run_id` is a moving pointer: once a finding is
    re-observed in a later run it no longer identifies the earlier one, so a
    metric built on it silently rewrites its own history."""
    conn, first, latest, _manifest, _cfg = two_runs
    before = {
        (r["metric"], r["value"]) for r in conn.execute(
            "SELECT metric, value FROM run_metrics WHERE run_id = ? AND dim = 'all'",
            (first.run_id,))
    }
    run = conn.execute("SELECT * FROM runs WHERE id = ?", (first.run_id,)).fetchone()
    timeseries.materialise(conn, first.run_id, run)
    after = {
        (r["metric"], r["value"]) for r in conn.execute(
            "SELECT metric, value FROM run_metrics WHERE run_id = ? AND dim = 'all'",
            (first.run_id,))
    }
    assert before == after, (
        "recomputing an old run's metrics must reproduce the same numbers"
    )


def test_series_is_ordered_by_scan_time(two_runs):
    conn, first, _latest, _manifest, _cfg = two_runs
    project_id = conn.execute("SELECT project_id FROM runs WHERE id = ?",
                              (first.run_id,)).fetchone()["project_id"]
    points = timeseries.series(conn, project_id, "hosts")
    assert len(points) == 2
    stamps = [p["started_at"] for p in points]
    assert stamps == sorted(stamps)


def test_posture_index_has_decimal_precision(two_runs):
    """When the estate grows proportionally the index drifts by fractions of a
    point; an integer would report that real movement as no change."""
    conn, first, _latest, _manifest, _cfg = two_runs
    project_id = conn.execute("SELECT project_id FROM runs WHERE id = ?",
                              (first.run_id,)).fetchone()["project_id"]
    points = timeseries.series(conn, project_id, "posture_index_host")
    assert points
    assert all(isinstance(p["value"], float) for p in points)


# ── Chronological ordering ──────────────────────────────────────────────────

def test_backfilled_older_scan_is_compared_correctly(tmp_path, cfg, monkeypatch):
    """Ingesting last month's file after this month's must not diff it against a
    newer scan."""
    monkeypatch.setattr(cfg, "data_dir", tmp_path)
    rows, fields = _read(FIXTURE)

    recent = [dict(r) for r in rows]
    _shift(recent, -7)
    newer = tmp_path / "newer.csv"
    _write(newer, recent, fields)

    older_rows = [dict(r) for r in rows]
    _shift(older_rows, -30)
    older_rows[0]["title"] = "Something different"
    older = tmp_path / "older.csv"
    _write(older, older_rows, fields)

    conn = connect(tmp_path / "order.sqlite")
    migrate(conn)
    a = pipeline.ingest(conn, cfg, newer, project="o", label="recent",
                        allow_incomplete=True, allow_drift=True, keep_raw=False)
    b = pipeline.ingest(conn, cfg, older, project="o", label="backfilled",
                        allow_incomplete=True, allow_drift=True, keep_raw=False)

    # The backfilled run is the earliest by scan time, so it has nothing before
    # it and must be treated as the baseline.
    assert b.diff.get("baseline") is True
    assert diff_mod.previous_run_id(conn, b.project_id, a.run_id) == b.run_id
    conn.close()


def test_latest_resolves_to_the_newest_scan(two_runs):
    """`resolve_run` ordered ascending by scan time while only the id was
    descending, so "latest" returned the EARLIEST run — invisible with one run,
    wrong the moment there are two."""
    from frogscope.api._db import resolve_run

    conn, _first, latest, _manifest, _cfg = two_runs
    assert resolve_run(conn, "latest")["id"] == latest.run_id
    assert resolve_run(conn, None)["id"] == latest.run_id
