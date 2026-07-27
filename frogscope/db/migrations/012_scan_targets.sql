-- v2: what kind of thing a run was pointed at, and what the collectors
-- actually managed. Without this, "why does this run have 60,000 endpoints"
-- has no answer in six months -- same reasoning as 008_scans.sql's scan_json.

ALTER TABLE runs ADD COLUMN target_kind TEXT NOT NULL DEFAULT 'domain';
ALTER TABLE runs ADD COLUMN correlated  INTEGER NOT NULL DEFAULT 0;

-- Per-collector outcome: version, ran/skipped, why, how much it produced.
-- This is what stops an uncorrelated (or partially-correlated) run from
-- silently reading as "the estate has no third-party hosting" -- the UI can
-- say "asnmap did not run: no API key" instead of reporting zero.
CREATE TABLE IF NOT EXISTS run_collectors (
    run_id      INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    tool        TEXT NOT NULL,
    version     TEXT,
    ran         INTEGER NOT NULL DEFAULT 0,
    exit_code   INTEGER,
    skip_reason TEXT,
    inputs      INTEGER NOT NULL DEFAULT 0,
    outputs     INTEGER NOT NULL DEFAULT 0,
    duration_s  REAL,
    PRIMARY KEY (run_id, tool)
);
