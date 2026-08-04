"""End-to-end ingest, query, and idempotency tests.

Counts are asserted as *invariants and reconciliations*, never as literals — the
source scan grows while it runs, so any hardcoded row count would be both wrong
and misleading.
"""

from __future__ import annotations

import csv
from datetime import UTC
from pathlib import Path

import pytest

from frogscope.config import load_config
from frogscope.db.connection import connect
from frogscope.db.migrate import current_version, discover, migrate
from frogscope.ingest import pipeline
from frogscope.query.catalog import Catalog
from frogscope.query.facets import compute, query_endpoints
from frogscope.query.filters import FilterError, compile_filters, compile_sort

FIXTURE = Path(__file__).parent / "fixtures" / "sample.csv"


@pytest.fixture(scope="module")
def cfg():
    return load_config()


@pytest.fixture()
def db(tmp_path, cfg, monkeypatch):
    monkeypatch.setenv("FROGSCOPE_DB", str(tmp_path / "test.sqlite"))
    conn = connect(tmp_path / "test.sqlite")
    migrate(conn)
    yield conn
    conn.close()


@pytest.fixture()
def ingested(db, cfg, tmp_path, monkeypatch):
    monkeypatch.setattr(cfg, "data_dir", tmp_path)
    return pipeline.ingest(db, cfg, FIXTURE, project="test", label="fixture",
                           allow_incomplete=True, keep_raw=False)


# ── Migrations ──────────────────────────────────────────────────────────────

def test_migrations_are_discoverable_and_uniquely_numbered():
    found = discover()
    assert found, "no migrations found"
    numbers = [n for n, _ in found]
    assert len(numbers) == len(set(numbers))
    assert numbers == sorted(numbers)


def test_migrate_is_idempotent_and_records_the_version(tmp_path):
    conn = connect(tmp_path / "m.sqlite")
    first = migrate(conn)
    assert first
    assert current_version(conn) == max(first)
    assert migrate(conn) == [], "re-running should apply nothing"
    conn.close()


def test_a_new_migration_is_applied_rather_than_silently_skipped(tmp_path):
    """frogy_web's init_db() returns early when user_version >= SCHEMA_VERSION,
    so any later schema edit silently never lands.

    Here the ledger records each migration individually, so a newly added file is
    picked up while already-applied ones are not re-run — which matters because
    ALTER TABLE ADD COLUMN cannot be made idempotent in SQLite.
    """
    from frogscope.db import migrate as migrate_mod

    conn = connect(tmp_path / "m2.sqlite")
    first = migrate(conn)
    assert first

    recorded = {r["number"] for r in conn.execute(
        "SELECT number FROM schema_migrations")}
    assert recorded == set(first)

    # Simulate a new migration file appearing after the DB was already migrated.
    highest = max(first)
    new_file = migrate_mod.MIGRATIONS_DIR / f"{highest + 1:03d}_test_probe.sql"
    new_file.write_text("CREATE TABLE probe_marker (id INTEGER PRIMARY KEY);")
    try:
        applied_now = migrate(conn)
        assert applied_now == [highest + 1], "a new migration must be applied"
        assert conn.execute(
            "SELECT name FROM sqlite_master WHERE name='probe_marker'"
        ).fetchone() is not None
        # And it must not run twice.
        assert migrate(conn) == []
    finally:
        new_file.unlink()
        conn.close()


# ── Ingest invariants ───────────────────────────────────────────────────────

def test_ingest_produces_one_row_per_unique_host_port(ingested, db):
    """The core grain invariant. Not a literal count — the relationship."""
    rows = db.execute(
        "SELECT COUNT(*) n, COUNT(DISTINCT endpoint_key) d FROM endpoints "
        "WHERE run_id = ?", (ingested.run_id,),
    ).fetchone()
    assert rows["n"] == rows["d"] == ingested.endpoint_count


def test_endpoint_count_reconciles_with_the_source_csv(ingested):
    with FIXTURE.open() as fh:
        raw = list(csv.DictReader(fh))
    expected = len({
        (r["host"].strip().rstrip(".").lower(), r["port"]) for r in raw
    })
    assert ingested.endpoint_count == expected
    assert ingested.row_count == len(raw)
    assert ingested.endpoint_count <= ingested.row_count


def test_host_count_reconciles_with_the_source_csv(ingested):
    with FIXTURE.open() as fh:
        raw = list(csv.DictReader(fh))
    expected = len({r["host"].strip().rstrip(".").lower() for r in raw})
    assert ingested.host_count == expected


def test_every_endpoint_key_is_lowercase(ingested, db):
    rows = db.execute(
        "SELECT endpoint_key FROM endpoints WHERE run_id = ?", (ingested.run_id,)
    ).fetchall()
    assert all(r["endpoint_key"] == r["endpoint_key"].lower() for r in rows)


def test_all_durations_parsed(ingested, db):
    """An unparsed duration means the mixed-unit handling regressed."""
    unparsed = db.execute(
        "SELECT COUNT(*) n FROM endpoints WHERE run_id = ? AND response_ms IS NULL",
        (ingested.run_id,),
    ).fetchone()["n"]
    assert unparsed == 0


def test_run_window_comes_from_the_data_not_ingest_time(ingested, db):
    """So backfilling an older CSV lands correctly in the timeline."""
    run = db.execute("SELECT * FROM runs WHERE id = ?", (ingested.run_id,)).fetchone()
    assert run["started_at"] <= run["completed_at"]
    assert run["started_at"].startswith("2026")


def test_raw_record_retains_every_source_column(ingested, db):
    import json
    row = db.execute(
        "SELECT raw_json FROM endpoints WHERE run_id = ? LIMIT 1", (ingested.run_id,)
    ).fetchone()
    with FIXTURE.open() as fh:
        source_columns = set(next(csv.reader(fh)))
    assert set(json.loads(row["raw_json"])) >= source_columns


def test_column_census_covers_every_source_column(ingested, db):
    with FIXTURE.open() as fh:
        source_columns = set(next(csv.reader(fh)))
    stored = {
        r["column_name"] for r in db.execute(
            "SELECT column_name FROM run_columns WHERE run_id = ?", (ingested.run_id,))
    }
    assert stored == source_columns


def test_host_rollup_exists_for_every_host(ingested, db):
    hosts_in_endpoints = db.execute(
        "SELECT COUNT(DISTINCT host) n FROM endpoints WHERE run_id = ?",
        (ingested.run_id,)).fetchone()["n"]
    hosts_in_rollup = db.execute(
        "SELECT COUNT(*) n FROM host_rollup WHERE run_id = ?",
        (ingested.run_id,)).fetchone()["n"]
    assert hosts_in_endpoints == hosts_in_rollup == ingested.host_count


# ── Idempotency ─────────────────────────────────────────────────────────────

def test_reingesting_the_same_file_is_refused(ingested, db, cfg, tmp_path, monkeypatch):
    monkeypatch.setattr(cfg, "data_dir", tmp_path)
    with pytest.raises(pipeline.DuplicateRun) as exc:
        pipeline.ingest(db, cfg, FIXTURE, project="test",
                        allow_incomplete=True, keep_raw=False)
    assert exc.value.existing["run_id"] == ingested.run_id


def test_reordered_columns_still_count_as_a_duplicate(ingested, db, cfg, tmp_path,
                                                     monkeypatch):
    """A byte hash alone would miss this; the content hash catches it."""
    monkeypatch.setattr(cfg, "data_dir", tmp_path)
    with FIXTURE.open() as fh:
        rows = list(csv.DictReader(fh))
    shuffled_fields = list(reversed(list(rows[0].keys())))
    other = tmp_path / "reordered.csv"
    with other.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=shuffled_fields)
        writer.writeheader()
        writer.writerows(reversed(rows))

    with pytest.raises(pipeline.DuplicateRun):
        pipeline.ingest(db, cfg, other, project="test",
                        allow_incomplete=True, keep_raw=False)


def test_force_allows_reingest_and_marks_it_a_duplicate(ingested, db, cfg, tmp_path,
                                                        monkeypatch):
    monkeypatch.setattr(cfg, "data_dir", tmp_path)
    again = pipeline.ingest(db, cfg, FIXTURE, project="test", force=True,
                            allow_incomplete=True, keep_raw=False)
    row = db.execute("SELECT duplicate_of FROM runs WHERE id = ?",
                     (again.run_id,)).fetchone()
    assert row["duplicate_of"] == ingested.run_id


def test_uppercasing_a_hostname_does_not_create_a_new_asset(db, cfg, tmp_path,
                                                            monkeypatch):
    """The case-drift trap, end to end."""
    monkeypatch.setattr(cfg, "data_dir", tmp_path)
    pipeline.ingest(db, cfg, FIXTURE, project="case", allow_incomplete=True,
                    keep_raw=False)
    before = db.execute(
        "SELECT COUNT(*) n FROM assets a JOIN projects p ON p.id = a.project_id "
        "WHERE p.slug = 'case' AND a.kind = 'endpoint'").fetchone()["n"]

    with FIXTURE.open() as fh:
        rows = list(csv.DictReader(fh))
    for row in rows:
        row["host"] = row["host"].upper()
        row["input"] = row["input"].upper()
    upper = tmp_path / "upper.csv"
    with upper.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    pipeline.ingest(db, cfg, upper, project="case", force=True,
                    allow_incomplete=True, keep_raw=False)
    after = db.execute(
        "SELECT COUNT(*) n FROM assets a JOIN projects p ON p.id = a.project_id "
        "WHERE p.slug = 'case' AND a.kind = 'endpoint'").fetchone()["n"]
    assert after == before, "uppercase hostnames created phantom assets"


# ── Completeness guard ──────────────────────────────────────────────────────

def test_hosts_submitted_and_ports_prescoped_round_trip_through_a_run(
        db, cfg, tmp_path, monkeypatch):
    """These two columns are what `quality.truncation_check` needs from the
    *previous* run to tell a truncated scan apart from a legitimately
    different one — persisted here, read back via `store.previous_run`."""
    from frogscope.ingest import store

    monkeypatch.setattr(cfg, "data_dir", tmp_path)
    result = pipeline.ingest(
        db, cfg, FIXTURE, project="hs-test", label="fixture",
        allow_incomplete=True, keep_raw=False,
        hosts_submitted=42, ports_prescoped=True)

    row = db.execute("SELECT * FROM runs WHERE id = ?",
                     (result.run_id,)).fetchone()
    assert row["hosts_submitted"] == 42
    assert row["ports_prescoped"] == 1

    project_id = row["project_id"]
    prev = store.previous_run(db, project_id)
    assert prev["hosts_submitted"] == 42
    assert prev["ports_prescoped"] == 1


def test_hosts_submitted_defaults_to_null_for_an_upload(db, cfg, tmp_path,
                                                          monkeypatch):
    monkeypatch.setattr(cfg, "data_dir", tmp_path)
    result = pipeline.ingest(
        db, cfg, FIXTURE, project="upload-test", label="fixture",
        allow_incomplete=True, keep_raw=False)

    row = db.execute("SELECT * FROM runs WHERE id = ?",
                     (result.run_id,)).fetchone()
    assert row["hosts_submitted"] is None
    assert row["ports_prescoped"] is None


def test_in_progress_scan_is_refused_by_default(db, cfg, tmp_path, monkeypatch):
    """A truncated scan becomes a permanent fake improvement in the trendline."""
    from datetime import datetime, timedelta
    monkeypatch.setattr(cfg, "data_dir", tmp_path)

    with FIXTURE.open() as fh:
        rows = list(csv.DictReader(fh))
    now = datetime.now(UTC)
    for i, row in enumerate(rows):
        row["timestamp"] = (now - timedelta(seconds=i)).isoformat()
    fresh = tmp_path / "fresh.csv"
    with fresh.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    with pytest.raises(pipeline.IncompleteScan):
        pipeline.ingest(db, cfg, fresh, project="fresh", keep_raw=False)

    result = pipeline.ingest(db, cfg, fresh, project="fresh",
                             allow_incomplete=True, keep_raw=False)
    assert result.warnings
    row = db.execute("SELECT incomplete FROM runs WHERE id = ?",
                     (result.run_id,)).fetchone()
    assert row["incomplete"] == 1


# ── Query layer ─────────────────────────────────────────────────────────────

def test_filters_reconcile_with_direct_sql(ingested, db, cfg):
    catalog = Catalog(cfg)
    for column, value, sql in [
        ("origin_exposed", [True], "origin_exposed = 1"),
        ("scan_artifact", [True], "scan_artifact = 1"),
        ("scheme", ["https"], "scheme = 'https'"),
    ]:
        result = query_endpoints(db, ingested.run_id, catalog,
                                 filters={column: value}, page_size=1)
        direct = db.execute(
            f"SELECT COUNT(*) n FROM endpoints WHERE run_id = ? AND {sql}",
            (ingested.run_id,)).fetchone()["n"]
        assert result["total"] == direct, column


def test_facet_counts_reconcile_with_group_by(ingested, db, cfg):
    catalog = Catalog(cfg)
    facets = compute(db, ingested.run_id, catalog, fields=["response_class"])
    from_facets = {str(o["value"]): o["count"] for o in facets["response_class"]}
    from_sql = {
        str(r["response_class"]): r["n"] for r in db.execute(
            "SELECT response_class, COUNT(*) n FROM endpoints WHERE run_id = ? "
            "GROUP BY 1", (ingested.run_id,))
    }
    assert from_facets == from_sql


def test_facets_exclude_their_own_filter(ingested, db, cfg):
    """Otherwise picking a value zeroes out every alternative and you can no
    longer see or switch to the others."""
    catalog = Catalog(cfg)
    unfiltered = compute(db, ingested.run_id, catalog, fields=["scheme"])
    filtered = compute(db, ingested.run_id, catalog,
                       filters={"scheme": ["https"]}, fields=["scheme"])
    assert len(filtered["scheme"]) == len(unfiltered["scheme"])


def test_list_column_filtering_uses_element_boundaries(ingested, db, cfg):
    catalog = Catalog(cfg)
    result = query_endpoints(db, ingested.run_id, catalog,
                             filters={"tech": {"values": ["HSTS"], "mode": "any"}},
                             page_size=1)
    direct = db.execute(
        "SELECT COUNT(*) n FROM endpoints WHERE run_id = ? AND EXISTS "
        "(SELECT 1 FROM json_each(endpoints.lists_json,'$.tech') je "
        " WHERE lower(je.value) = 'hsts')", (ingested.run_id,)).fetchone()["n"]
    assert result["total"] == direct


def test_unknown_column_is_rejected_before_reaching_sql(cfg):
    catalog = Catalog(cfg)
    with pytest.raises(FilterError):
        compile_filters({"host; DROP TABLE endpoints": ["x"]}, catalog)
    with pytest.raises(FilterError):
        compile_sort("nonexistent_column", catalog)


def test_sort_is_stable(cfg):
    catalog = Catalog(cfg)
    assert compile_sort("port", catalog).endswith('"endpoint_key" ASC')
    assert '"port" DESC' in compile_sort("-port", catalog)


def test_negation_filter(ingested, db, cfg):
    catalog = Catalog(cfg)
    excluded = query_endpoints(db, ingested.run_id, catalog,
                              filters={"scheme": ["!https"]}, page_size=1)
    direct = db.execute(
        "SELECT COUNT(*) n FROM endpoints WHERE run_id = ? AND "
        "(scheme IS NULL OR scheme NOT IN ('https'))",
        (ingested.run_id,)).fetchone()["n"]
    assert excluded["total"] == direct


def test_range_filter(ingested, db, cfg):
    catalog = Catalog(cfg)
    result = query_endpoints(db, ingested.run_id, catalog,
                             filters={"port": {"min": 443, "max": 443}}, page_size=1)
    direct = db.execute(
        "SELECT COUNT(*) n FROM endpoints WHERE run_id = ? AND port = 443",
        (ingested.run_id,)).fetchone()["n"]
    assert result["total"] == direct


def test_pagination_covers_every_row_exactly_once(ingested, db, cfg):
    catalog = Catalog(cfg)
    seen: set[str] = set()
    page = 1
    while True:
        result = query_endpoints(db, ingested.run_id, catalog,
                                 page=page, page_size=7)
        if not result["rows"]:
            break
        for row in result["rows"]:
            assert row["endpoint_key"] not in seen, "row appeared on two pages"
            seen.add(row["endpoint_key"])
        if page >= result["pages"]:
            break
        page += 1
    assert len(seen) == ingested.endpoint_count


# ── Config ──────────────────────────────────────────────────────────────────

def test_config_validates_and_columns_match_the_catalog(cfg):
    catalog = Catalog(cfg)
    assert catalog.columns
    assert catalog.default_visible()
    for preset in (cfg.columns.get("presets") or {}).values():
        for key in preset["columns"]:
            assert key in catalog, key


def test_no_port_is_in_two_categories(cfg):
    seen: dict[int, str] = {}
    for name, spec in (cfg.ports.get("categories") or {}).items():
        for port in spec.get("ports", []):
            assert port not in seen, f"port {port} in {seen.get(port)} and {name}"
            seen[port] = name


def test_every_probed_port_has_a_category(ingested, db, cfg):
    """A port falling through to 'other' means the config is behind the scan."""
    uncategorised = db.execute(
        "SELECT DISTINCT port FROM endpoints WHERE run_id = ? "
        "AND (port_category IS NULL OR port_category = 'other')",
        (ingested.run_id,)).fetchall()
    assert not [r["port"] for r in uncategorised]
