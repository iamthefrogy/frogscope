"""Projects and deletion: the only write paths besides ingest."""

from __future__ import annotations

from datetime import UTC
from pathlib import Path

import pytest

from frogscope.config import load_config
from frogscope.db.connection import connect
from frogscope.db.migrate import migrate
from frogscope.ingest import pipeline, store
from frogscope.server import create_app

FIXTURE = Path(__file__).parent / "fixtures" / "sample.csv"


@pytest.fixture()
def cfg(tmp_path, monkeypatch):
    conf = load_config()
    monkeypatch.setattr(conf, "data_dir", tmp_path)
    return conf


@pytest.fixture()
def db(cfg):
    conn = connect(cfg.db_path)
    migrate(conn)
    yield conn
    conn.close()


@pytest.fixture()
def client(cfg, monkeypatch):
    monkeypatch.setattr("frogscope.config.load_config", lambda *a, **k: cfg)
    app = create_app(cfg)
    app.config.update(TESTING=True)
    with app.test_client() as c:
        # v2: every /api/* route now needs the access key (see server.py's
        # before_request gate). `environ_base` merges into every request
        # this client makes, so the whole file's existing calls don't need
        # to pass the header individually — and this still exercises the
        # real gate, since a wrong value here would 401 every single test.
        c.environ_base["HTTP_X_AUTH_KEY"] = app.config["FROGSCOPE_AUTH_KEY"]
        yield c


def _ingest(conn, cfg, project, label, path=FIXTURE):
    return pipeline.ingest(conn, cfg, path, project=project, label=label,
                           allow_incomplete=True, allow_drift=True)


# ── Creating ────────────────────────────────────────────────────────────────

def test_a_name_is_enough_to_create_a_project(client):
    """Somebody typing "Acme Corp" should not have to know the CLI wants
    `acme-corp`."""
    res = client.post("/api/projects", json={"name": "Acme Corp"})
    assert res.status_code == 201
    assert res.get_json()["slug"] == "acme-corp"


def test_slug_derivation_strips_punctuation(client):
    res = client.post("/api/projects", json={"name": "Acme  Corp. (EU)!"})
    assert res.get_json()["slug"] == "acme-corp-eu"


def test_a_project_needs_a_name(client):
    assert client.post("/api/projects", json={}).status_code == 400
    assert client.post("/api/projects", json={"name": "   "}).status_code == 400


def test_a_name_that_slugifies_to_nothing_is_rejected(client):
    """"!!!" becomes an empty slug, which would collide with every other empty
    one and cannot be addressed in a URL."""
    assert client.post("/api/projects", json={"name": "!!!"}).status_code == 400


def test_a_duplicate_slug_is_refused_not_merged(client):
    """Silently reusing the project would file a new target's scans under an
    existing one, and diffs would then compare unrelated estates."""
    client.post("/api/projects", json={"name": "Acme Corp"})
    res = client.post("/api/projects", json={"name": "acme corp"})
    assert res.status_code == 409
    assert "already exists" in res.get_json()["error"]


def test_an_explicit_bad_slug_is_rejected(client):
    res = client.post("/api/projects",
                      json={"name": "X", "slug": "has spaces!"})
    assert res.status_code == 400


def test_project_stats_report_what_is_there(db, cfg):
    _ingest(db, cfg, "p1", "r1")
    project_id = db.execute("SELECT id FROM projects WHERE slug='p1'").fetchone()["id"]
    stats = store.project_stats(db, project_id)
    assert stats["runs"] == 1
    assert stats["endpoints"] > 0
    assert len(stats["run_keys"]) == 1


# ── Confirmation is enforced server-side ────────────────────────────────────

def test_deleting_a_project_needs_the_exact_slug(client):
    """A browser `confirm()` is a courtesy. The server is what stands between a
    mis-typed request and an irreversible delete."""
    client.post("/api/projects", json={"name": "Acme Corp"})
    assert client.delete("/api/projects/acme-corp", json={}).status_code == 400
    assert client.delete("/api/projects/acme-corp",
                         json={"confirm": "wrong"}).status_code == 400
    assert client.delete("/api/projects/acme-corp",
                         json={"confirm": "acme-corp"}).status_code == 200


def test_reset_needs_a_phrase_not_a_boolean(client):
    """A stray `{"confirm": true}` copied from a snippet must not be able to wipe
    an estate's scan history."""
    assert client.post("/api/reset", json={"confirm": True}).status_code == 400
    assert client.post("/api/reset", json={"confirm": 1}).status_code == 400
    assert client.post("/api/reset",
                       json={"confirm": "delete everything"}).status_code == 400
    assert client.post("/api/reset",
                       json={"confirm": "DELETE EVERYTHING"}).status_code == 200


def test_deleting_an_unknown_project_is_a_404_not_a_silent_success(client):
    assert client.delete("/api/projects/nope",
                         json={"confirm": "nope"}).status_code == 404


def test_deleting_a_run_needs_its_run_key(client, db, cfg):
    result = _ingest(db, cfg, "p1", "r1")
    db.commit()
    assert client.delete(f"/api/runs/{result.run_id}",
                         json={"confirm": "guess"}).status_code == 400
    assert client.delete(f"/api/runs/{result.run_id}",
                         json={"confirm": result.run_key}).status_code == 200


# ── Deleting actually deletes ───────────────────────────────────────────────

def test_deleting_a_project_leaves_no_orphans(db, cfg):
    _ingest(db, cfg, "p1", "r1")
    project_id = db.execute("SELECT id FROM projects WHERE slug='p1'").fetchone()["id"]
    store.delete_project(db, project_id, raw_dir=cfg.raw_dir)

    for table in ("findings", "assets", "changes", "asset_presence",
                  "saved_views", "ingest_files", "notifications",
                  "asset_attr_history"):
        left = db.execute(
            f"SELECT COUNT(*) AS n FROM {table} "
            f"WHERE project_id NOT IN (SELECT id FROM projects)").fetchone()["n"]
        assert left == 0, table
    assert db.execute("SELECT COUNT(*) AS n FROM endpoints").fetchone()["n"] == 0


def test_deleting_a_project_clears_the_search_index(db, cfg):
    """`endpoints_fts` has no foreign key, so a cascade drops the endpoints and
    leaves the index — and the search box keeps returning hosts that are gone."""
    _ingest(db, cfg, "p1", "r1")
    assert db.execute("SELECT COUNT(*) AS n FROM endpoints_fts").fetchone()["n"] > 0
    project_id = db.execute("SELECT id FROM projects WHERE slug='p1'").fetchone()["id"]
    store.delete_project(db, project_id, raw_dir=cfg.raw_dir)
    assert db.execute("SELECT COUNT(*) AS n FROM endpoints_fts").fetchone()["n"] == 0


def test_deleting_a_run_clears_only_its_own_index_rows(db, cfg, tmp_path):
    import csv

    first = _ingest(db, cfg, "p1", "r1")
    # A second run needs different source bytes or it is refused as a duplicate.
    with FIXTURE.open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        fields, rows = reader.fieldnames, list(reader)
    for row in rows:
        row["cdn_name"] = ""
    second_path = tmp_path / "second.csv"
    with second_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    second = _ingest(db, cfg, "p1", "r2", second_path)

    before = db.execute("SELECT COUNT(*) AS n FROM endpoints_fts "
                        "WHERE endpoint_key LIKE ?",
                        (f"{second.run_id}:%",)).fetchone()["n"]
    assert before > 0

    store.delete_run(db, first.run_id)
    db.commit()
    after = db.execute("SELECT COUNT(*) AS n FROM endpoints_fts "
                       "WHERE endpoint_key LIKE ?",
                       (f"{second.run_id}:%",)).fetchone()["n"]
    assert after == before, "the surviving run must keep its index rows"


def test_deleting_one_project_does_not_touch_another(db, cfg, tmp_path):
    import csv

    _ingest(db, cfg, "keep", "r1")
    with FIXTURE.open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        fields, rows = reader.fieldnames, list(reader)
    for row in rows:
        row["cdn_name"] = ""
    other = tmp_path / "other.csv"
    with other.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    _ingest(db, cfg, "drop", "r1", other)

    keep_endpoints = db.execute(
        "SELECT COUNT(*) AS n FROM endpoints e JOIN runs r ON r.id = e.run_id "
        "JOIN projects p ON p.id = r.project_id WHERE p.slug = 'keep'"
    ).fetchone()["n"]

    drop_id = db.execute("SELECT id FROM projects WHERE slug='drop'").fetchone()["id"]
    store.delete_project(db, drop_id, raw_dir=cfg.raw_dir)

    assert db.execute(
        "SELECT COUNT(*) AS n FROM endpoints e JOIN runs r ON r.id = e.run_id "
        "JOIN projects p ON p.id = r.project_id WHERE p.slug = 'keep'"
    ).fetchone()["n"] == keep_endpoints
    assert db.execute(
        "SELECT COUNT(*) AS n FROM projects WHERE slug='keep'").fetchone()["n"] == 1


def test_deleting_removes_the_archived_source_file(db, cfg):
    result = _ingest(db, cfg, "p1", "r1")
    archive = cfg.raw_dir / f"{result.run_key}.csv.gz"
    assert archive.exists()
    project_id = db.execute("SELECT id FROM projects WHERE slug='p1'").fetchone()["id"]
    store.delete_project(db, project_id, raw_dir=cfg.raw_dir)
    assert not archive.exists()


def test_reset_keeps_the_schema(db, cfg):
    """The alternative is deleting the database file, which the running server
    still holds open."""
    _ingest(db, cfg, "p1", "r1")
    before = db.execute("SELECT COUNT(*) AS n FROM schema_migrations").fetchone()["n"]
    counts = store.reset_all(db, raw_dir=cfg.raw_dir)
    assert counts["runs"] == 1
    assert db.execute("SELECT COUNT(*) AS n FROM schema_migrations"
                      ).fetchone()["n"] == before
    for table in ("projects", "runs", "endpoints", "endpoints_fts", "findings"):
        assert db.execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone()["n"] == 0


def test_reset_leaves_the_store_usable(db, cfg):
    """A reset that corrupts the FTS shadow tables would only fail on the next
    ingest, long after the action that caused it."""
    _ingest(db, cfg, "p1", "r1")
    store.reset_all(db, raw_dir=cfg.raw_dir)
    result = _ingest(db, cfg, "fresh", "r1")
    assert result.endpoint_count > 0
    assert db.execute("SELECT COUNT(*) AS n FROM endpoints_fts").fetchone()["n"] > 0


def test_reset_removes_archived_files(db, cfg):
    _ingest(db, cfg, "p1", "r1")
    assert list(cfg.raw_dir.glob("*.csv.gz"))
    counts = store.reset_all(db, raw_dir=cfg.raw_dir)
    assert counts["raw_archives"] == 1
    assert not list(cfg.raw_dir.glob("*.csv.gz"))


# ── The upload path ─────────────────────────────────────────────────────────

def test_an_uploaded_file_is_not_judged_by_its_mtime(db, cfg):
    """A browser upload is written to a temp file at request time, so its mtime is
    always "a moment ago". Applying the check there would fire on every single
    upload and train people to tick the override permanently, defeating a guard
    that exists for a real reason."""
    import time
    from datetime import datetime

    from frogscope.ingest import quality

    # Not passing the mtime at all: no mtime warning, obviously.
    warnings = quality.completeness_check(
        [{"port": 443, "scanned_at": "2020-01-01T00:00:00+00:00"}],
        source_mtime=None)
    assert not any("modified" in w for w in warnings)

    # Passing it, with observations that are ALSO fresh — the case the guard
    # exists for. Old observations plus a new mtime means a copied or checked-out
    # file, which has its own test.
    now = datetime.now(UTC).isoformat()
    fresh = quality.completeness_check([{"port": 443, "scanned_at": now}],
                                       source_mtime=time.time())
    assert any("modified" in w for w in fresh)


def test_ingest_still_checks_mtime_for_a_path_on_disk(db, cfg, tmp_path):
    """The guard must keep working for `frogscope ingest <file>`, where the file
    genuinely may still be being written by httpx."""
    import inspect

    signature = inspect.signature(pipeline.ingest)
    assert signature.parameters["trust_mtime"].default is True


def test_the_upload_route_disables_the_mtime_check():
    source = Path(__import__("frogscope.api.routes", fromlist=["x"]).__file__)
    text = source.read_text(encoding="utf-8")
    assert "trust_mtime=False" in text


# ── Wiring ──────────────────────────────────────────────────────────────────

def test_the_api_lists_projects_with_run_counts(client, db, cfg):
    _ingest(db, cfg, "p1", "r1")
    db.commit()
    rows = client.get("/api/projects").get_json()["projects"]
    assert rows and rows[0]["run_count"] == 1


def test_stats_endpoint_reports_before_a_delete_is_offered(client, db, cfg):
    _ingest(db, cfg, "p1", "r1")
    db.commit()
    payload = client.get("/api/projects/p1/stats").get_json()
    assert payload["stats"]["runs"] == 1
    assert payload["project"]["slug"] == "p1"


def test_deleting_a_run_says_diffs_were_left_alone(client, db, cfg):
    """Recomputing them would silently rewrite history the user has already read."""
    result = _ingest(db, cfg, "p1", "r1")
    db.commit()
    out = client.delete(f"/api/runs/{result.run_id}",
                        json={"confirm": result.run_key}).get_json()
    assert "reindex" in out["note"]


def test_delete_controls_are_absent_from_the_offline_export():
    """`fetch` is shimmed in the export, so a live-looking delete button would
    silently do nothing."""
    source = (Path("frogscope/static/app/manage.js")).read_text(encoding="utf-8")
    assert "if (SNAP) return null;" in source


def test_manage_module_is_bundled_into_the_offline_export():
    """`views` and `main` import it, so leaving it out of the import map breaks
    the whole export at load time."""
    source = Path("frogscope/export/snapshot.py").read_text(encoding="utf-8")
    assert '"manage"' in source


# ── The drift override (regression) ─────────────────────────────────────────

def test_drift_and_incompleteness_ask_for_different_overrides():
    """The bug: a suspicious change in scale raised the same exception as a
    truncated file, so the UI offered `allow_incomplete` — which does not ungate
    the drift check. The button could never work, and the upload appeared stuck."""
    assert pipeline.IncompleteScan("m", []).override == "allow_incomplete"
    assert pipeline.ScaleDrift("m", []).override == "allow_drift"


def test_scale_drift_is_still_an_incomplete_scan():
    """Existing `except IncompleteScan` handlers must keep catching it."""
    assert issubclass(pipeline.ScaleDrift, pipeline.IncompleteScan)


def test_a_shrunken_run_raises_scale_drift_not_plain_incompleteness(db, cfg,
                                                                    tmp_path):
    import csv

    _ingest(db, cfg, "p1", "big")
    with FIXTURE.open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        fields, rows = reader.fieldnames, list(reader)
    small = tmp_path / "small.csv"
    with small.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows[:8])          # far more than 30% smaller

    with pytest.raises(pipeline.ScaleDrift) as caught:
        pipeline.ingest(db, cfg, small, project="p1", label="small",
                        allow_incomplete=True)
    assert caught.value.override == "allow_drift"


def test_the_offered_override_actually_ungates_the_ingest(db, cfg, tmp_path):
    """The point of the fix: whatever override is reported must let it through."""
    import csv

    _ingest(db, cfg, "p1", "big")
    with FIXTURE.open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        fields, rows = reader.fieldnames, list(reader)
    small = tmp_path / "small.csv"
    with small.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows[:8])

    try:
        pipeline.ingest(db, cfg, small, project="p1", label="small",
                        allow_incomplete=True)
        pytest.fail("expected a rejection")
    except pipeline.IncompleteScan as exc:
        override = exc.override

    result = pipeline.ingest(db, cfg, small, project="p1", label="small",
                             allow_incomplete=True, **{override: True})
    assert result.endpoint_count > 0
    # And the reason is kept on the run rather than discarded once accepted.
    assert any("changed by" in w for w in result.warnings)


def test_the_api_tells_the_ui_which_override_to_offer(client, db, cfg, tmp_path):
    import csv
    import io
    import time

    _ingest(db, cfg, "p1", "big")
    db.commit()
    with FIXTURE.open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        fields, rows = reader.fieldnames, list(reader)
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fields)
    writer.writeheader()
    writer.writerows(rows[:8])
    payload = buffer.getvalue().encode()

    started = client.post("/api/ingest", data={
        "file": (io.BytesIO(payload), "small.csv"),
        "project": "p1", "label": "small", "allow_incomplete": "1",
    }, content_type="multipart/form-data").get_json()

    for _ in range(60):
        job = client.get(f"/api/ingest/{started['job_id']}").get_json()
        if job["state"] != "running":
            break
        time.sleep(0.2)
    assert job["state"] == "incomplete"
    assert job["override"] == "allow_drift"


def test_a_duplicate_names_its_own_override(client, db, cfg):
    import io
    import time

    _ingest(db, cfg, "p1", "r1")
    db.commit()
    started = client.post("/api/ingest", data={
        "file": (io.BytesIO(FIXTURE.read_bytes()), "same.csv"),
        "project": "p1", "label": "again", "allow_incomplete": "1",
    }, content_type="multipart/form-data").get_json()

    for _ in range(60):
        job = client.get(f"/api/ingest/{started['job_id']}").get_json()
        if job["state"] != "running":
            break
        time.sleep(0.2)
    assert job["state"] == "duplicate"
    assert job["override"] == "force"


def test_the_cli_names_the_flag_that_matches_the_gate():
    source = Path("frogscope/cli.py").read_text(encoding="utf-8")
    assert 'exc.override.replace("_", "-")' in source, \
        "a hardcoded flag name would print the wrong one for drift"


def test_the_upload_ui_retries_the_file_it_already_holds():
    """"Drop the file again" is busywork, and it was also the instruction that
    never worked when the offered override was the wrong one."""
    source = Path("frogscope/static/app/manage.js").read_text(encoding="utf-8")
    assert "const [pending, setPending] = useState(null);" in source
    assert "retryWith" in source
    assert "job.override" in source, "the UI must use the server's override"


# ── The mtime guard needs corroboration (regression) ────────────────────────

def test_a_freshly_checked_out_file_is_not_treated_as_still_being_written():
    """`git clone` stamps every file with the clone time, so the committed example
    scan always looked "modified 0s ago" and the documented first command failed on
    every fresh checkout. A recent mtime only means anything if the observations
    inside the file are also recent."""
    import time

    from frogscope.ingest import quality

    old_records = [{"port": 443, "scanned_at": "2026-03-02T09:00:00+00:00"}]
    warnings = quality.completeness_check(old_records, source_mtime=time.time())
    assert not any("being written" in w for w in warnings), warnings


def test_a_genuinely_in_progress_scan_is_still_caught():
    """The guard must keep working for the case it exists for: httpx writing right
    now, so both the mtime AND the newest observation are seconds old."""
    import time
    from datetime import datetime

    from frogscope.ingest import quality

    now = datetime.now(UTC).isoformat()
    warnings = quality.completeness_check([{"port": 443, "scanned_at": now}],
                                          source_mtime=time.time())
    assert any("still be running" in w for w in warnings), warnings


def test_a_file_with_no_timestamps_still_gets_the_mtime_check():
    """With nothing to corroborate against, the mtime is the only signal there is,
    so it must not be discarded."""
    import time

    from frogscope.ingest import quality

    warnings = quality.completeness_check([{"port": 443}], source_mtime=time.time())
    assert any("being written" in w for w in warnings), warnings


# ── Facet selection (regression) ─────────────────────────────────────────────

def test_the_facet_filter_shape_helper_handles_both_filter_kinds():
    """`filter.values || filter` returns `Array.prototype.values` on an ARRAY — a
    truthy function. Stringifying it gave a selected set of
    `["function Values() { [native code] }"]`, so no checkbox ever matched and no
    tick ever appeared."""
    source = Path("frogscope/static/app/facets.js").read_text(encoding="utf-8")
    assert "function selectedValues(filter)" in source
    assert "filters[key].values || filters[key]" not in source, \
        "the buggy expression is back"
    assert "Array.isArray(filter.values)" in source


def test_facet_options_are_ordered_independently_of_their_counts():
    """The server orders options by count. Re-sorting on every response made the row
    you had just clicked jump elsewhere, so the tick looked like it landed on the
    wrong option and the panel visibly shifted."""
    source = Path("frogscope/static/app/facets.js").read_text(encoding="utf-8")
    assert "localeCompare" in source, "options must be ordered by label, not count"
    assert "chosen.has(String(a.value))" in source, "selected options must pin to top"


def test_a_selected_option_cannot_vanish_from_the_list():
    """Once a value is the only one left, the server may stop returning it as an
    option — removing the only control that could unselect it."""
    source = Path("frogscope/static/app/facets.js").read_text(encoding="utf-8")
    assert "ordered.unshift" in source


def test_facet_rows_are_keyed_by_value():
    """Without a key, Preact reconciles by position, so a reordered list moves the
    tick to whatever option now sits at that index."""
    source = Path("frogscope/static/app/facets.js").read_text(encoding="utf-8")
    assert 'key=${String(option.value)}' in source


# ── Deleting a project is reachable where projects are managed ───────────────

def test_project_delete_sits_beside_the_project_selector():
    """It was only at the bottom of the page under "Delete data", which is where you
    look to wipe everything — not to remove one project. Each destructive action now
    sits beside its subject."""
    source = Path("frogscope/static/app/manage.js").read_text(encoding="utf-8")
    assert "Delete ${current.name}" in source
    assert "ConfirmProjectDelete" in source


def test_the_confirmation_states_what_will_be_lost():
    """"Are you sure?" is not consent. The counts come from the server before the
    button is offered."""
    source = Path("frogscope/static/app/manage.js").read_text(encoding="utf-8")
    assert "store.projectStats" in source
    assert "endpoint records" in source
    assert "archived source files" in source


def test_the_delete_button_needs_the_exact_slug_typed():
    source = Path("frogscope/static/app/manage.js").read_text(encoding="utf-8")
    assert "disabled=${busy || typed !== slug}" in source


def test_the_danger_zone_no_longer_duplicates_project_delete():
    """Two controls doing the same thing can disagree; one of them is then wrong."""
    source = Path("frogscope/static/app/manage.js").read_text(encoding="utf-8")
    assert "function DeleteProject(" not in source, "dead duplicate left behind"
    assert "ResetEverything" in source


def test_deleting_a_project_removes_the_project_itself(db, cfg):
    """Not only its scans — the project row goes too, so the name disappears from
    every picker."""
    _ingest(db, cfg, "gone", "r1")
    project_id = db.execute(
        "SELECT id FROM projects WHERE slug='gone'").fetchone()["id"]
    store.delete_project(db, project_id, raw_dir=cfg.raw_dir)
    assert db.execute("SELECT COUNT(*) AS n FROM projects "
                      "WHERE slug='gone'").fetchone()["n"] == 0


def test_deleting_a_project_flushes_every_table_that_referenced_it(db, cfg):
    """Migrations keep adding tables. This walks the schema rather than a hardcoded
    list, so a new table with a project_id cannot be forgotten."""
    _ingest(db, cfg, "gone", "r1")
    project_id = db.execute(
        "SELECT id FROM projects WHERE slug='gone'").fetchone()["id"]
    store.delete_project(db, project_id, raw_dir=cfg.raw_dir)

    tables = [r["name"] for r in db.execute(
        "SELECT name FROM sqlite_master WHERE type='table' "
        "AND name NOT LIKE 'sqlite_%' AND name NOT LIKE 'endpoints_fts_%'")]
    for table in tables:
        columns = {r[1] for r in db.execute(f"PRAGMA table_info({table})")}
        if "project_id" in columns:
            left = db.execute(
                f"SELECT COUNT(*) AS n FROM {table} WHERE project_id NOT IN "
                f"(SELECT id FROM projects)").fetchone()["n"]
            assert left == 0, f"{table} kept {left} orphaned row(s)"
        elif "run_id" in columns:
            left = db.execute(
                f"SELECT COUNT(*) AS n FROM {table} WHERE run_id IS NOT NULL "
                f"AND run_id NOT IN (SELECT id FROM runs)").fetchone()["n"]
            assert left == 0, f"{table} kept {left} orphaned row(s)"


# ── The first-run screen offers scanning only, no manual upload ─────────────

def test_setup_offers_only_the_scan_path():
    """Docker scanning is the primary, lightweight path — there is no reason
    to offer a second, manual-upload route on first run, or anywhere else in
    the UI. `Uploader` stays defined (unreferenced) rather than deleted, same
    precedent as other components retired from the nav but left in place."""
    source = Path("frogscope/static/app/manage.js").read_text(encoding="utf-8")
    assert "Option 1" not in source and "Option 2" not in source
    assert "ScanPanel" in source
    setup = source[source.index("export function SetupView"):]
    assert "Uploader" not in setup


def test_the_old_produce_one_with_httpx_card_is_gone():
    source = Path("frogscope/static/app/manage.js").read_text(encoding="utf-8")
    assert "No scan yet?" not in source


def test_manual_upload_is_not_offered_anywhere_in_the_ui():
    """The only remaining upload path is `frogscope ingest` on the CLI —
    dropped from Configuration (views.js's `RunsView`) the same way it was
    dropped from Setup."""
    source = Path("frogscope/static/app/views.js").read_text(encoding="utf-8")
    assert "Uploader" not in source


def test_setup_keeps_project_creation_and_deletion_available():
    source = Path("frogscope/static/app/manage.js").read_text(encoding="utf-8")
    setup = source[source.index("export function SetupView"):]
    assert "ProjectChooser" in setup
    assert "onDeleted" in setup


def test_the_setup_screen_is_full_width():
    """It was a 620px centred column, which left the two options cramped."""
    css = Path("frogscope/static/css/app.css").read_text(encoding="utf-8")
    assert ".setup-options" in css
    assert "auto-fit, minmax(420px, 1fr)" in css, "options must stack, not squeeze"
    assert "max-width: 620px" not in css


def test_the_embedded_scan_panel_does_not_nest_a_card():
    source = Path("frogscope/static/app/scan.js").read_text(encoding="utf-8")
    assert "embedded" in source
    assert "class=${embedded ? '' : 'card'}" in source
