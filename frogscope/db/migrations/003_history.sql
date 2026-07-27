-- Phase 4: run-over-run change detection, history, and trends.

-- Per-field changes between two runs.
--
-- frogy_web's `changes` table records only whole-asset added/removed/modified,
-- where "modified" means the integer score moved. That misses the changes that
-- matter most: a host losing its WAF, or a status flipping 403 to 200, at an
-- identical score. This table records the field, both values, and how much
-- attention the change deserves.
CREATE TABLE IF NOT EXISTS changes (
    id            INTEGER PRIMARY KEY,
    project_id    INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    run_id        INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    prev_run_id   INTEGER REFERENCES runs(id) ON DELETE SET NULL,
    asset_kind    TEXT NOT NULL DEFAULT 'endpoint',
    asset_key     TEXT NOT NULL,
    host          TEXT,
    change_type   TEXT NOT NULL,      -- added / removed / modified / returned
    field         TEXT,               -- null for added and removed
    before_json   TEXT,
    after_json    TEXT,
    added_json    TEXT,               -- set comparisons: members gained
    removed_json  TEXT,               -- set comparisons: members lost
    severity      TEXT NOT NULL DEFAULT 'low',
    direction     TEXT,               -- worse / better / lateral
    is_noisy      INTEGER NOT NULL DEFAULT 0,
    is_classification INTEGER NOT NULL DEFAULT 0,
    summary       TEXT,
    created_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_changes_run    ON changes(run_id, change_type);
CREATE INDEX IF NOT EXISTS idx_changes_asset  ON changes(project_id, asset_key);
CREATE INDEX IF NOT EXISTS idx_changes_field  ON changes(run_id, field);
CREATE INDEX IF NOT EXISTS idx_changes_sev    ON changes(run_id, severity);

-- Presence history per asset, as a compact string of 1/0 in run order.
--
-- Cheaper than a row per asset per run, and it makes flapping a string scan:
-- an asset that toggles repeatedly is unstable infrastructure or scan-scope
-- churn, and it must not dominate the "new assets" feed every week.
CREATE TABLE IF NOT EXISTS asset_presence (
    project_id      INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    asset_kind      TEXT NOT NULL,
    asset_key       TEXT NOT NULL,
    presence        TEXT NOT NULL DEFAULT '',  -- '1101' in chronological run order
    runs_seen       INTEGER NOT NULL DEFAULT 0,
    runs_absent     INTEGER NOT NULL DEFAULT 0,
    absent_streak   INTEGER NOT NULL DEFAULT 0,
    flap_count      INTEGER NOT NULL DEFAULT 0,
    is_flapping     INTEGER NOT NULL DEFAULT 0,
    stability       TEXT,                      -- new/stable/intermittent/disappeared
    first_seen_run  INTEGER REFERENCES runs(id) ON DELETE SET NULL,
    last_seen_run   INTEGER REFERENCES runs(id) ON DELETE SET NULL,
    PRIMARY KEY (project_id, asset_kind, asset_key)
);
CREATE INDEX IF NOT EXISTS idx_presence_flap ON asset_presence(project_id, is_flapping);

-- Sparse attribute history: a row only when a value actually changes.
--
-- Gives the drawer a complete per-attribute timeline at a small fraction of the
-- storage a dense per-run snapshot would need, and it is what answers "when did
-- this go from 403 to 200".
CREATE TABLE IF NOT EXISTS asset_attr_history (
    project_id  INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    asset_kind  TEXT NOT NULL DEFAULT 'endpoint',
    asset_key   TEXT NOT NULL,
    field       TEXT NOT NULL,
    run_id      INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    value_json  TEXT,
    changed_at  TEXT,
    PRIMARY KEY (project_id, asset_kind, asset_key, field, run_id)
);
CREATE INDEX IF NOT EXISTS idx_attr_hist ON asset_attr_history(project_id, asset_key, field);

-- Long-format metrics, so a trend chart is one indexed query rather than a
-- re-scan of every stored run, and adding a metric needs no schema change.
CREATE TABLE IF NOT EXISTS run_metrics (
    run_id    INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    metric    TEXT NOT NULL,
    dim       TEXT NOT NULL DEFAULT 'all',
    dim_value TEXT NOT NULL DEFAULT 'all',
    value     REAL NOT NULL,
    PRIMARY KEY (run_id, metric, dim, dim_value)
);
CREATE INDEX IF NOT EXISTS idx_metrics_metric ON run_metrics(metric, dim);

-- Diff rollup for the run, so the executive page needs no recomputation.
ALTER TABLE runs ADD COLUMN diff_json    TEXT;
ALTER TABLE runs ADD COLUMN prev_run_id  INTEGER REFERENCES runs(id) ON DELETE SET NULL;
