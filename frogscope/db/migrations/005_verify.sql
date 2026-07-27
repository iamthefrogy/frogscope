-- Phase 6: opt-in live verification, and the watch folder.

-- Verification is stored beside the run rather than overwriting the scan-derived
-- takeover grade. The scan said what it could see from the CSV; verification is a
-- later, independent observation that made network requests. Merging them would
-- lose that distinction, and the distinction is the point.
ALTER TABLE runs ADD COLUMN verify_json TEXT;

-- Files the watch folder has already handled, so a restart does not re-ingest
-- everything sitting in the directory.
CREATE TABLE IF NOT EXISTS watched_files (
    path        TEXT PRIMARY KEY,
    sha256      TEXT,
    run_id      INTEGER REFERENCES runs(id) ON DELETE SET NULL,
    outcome     TEXT NOT NULL,          -- ingested / duplicate / error / skipped
    message     TEXT,
    seen_at     TEXT NOT NULL
);
