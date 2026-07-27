-- Phase 5: saved views and ownership.

-- Named filter states, persisted server-side rather than in localStorage so a
-- view survives a different browser and can be shared with a colleague.
CREATE TABLE IF NOT EXISTS saved_views (
    id          INTEGER PRIMARY KEY,
    project_id  INTEGER REFERENCES projects(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    description TEXT,
    view        TEXT NOT NULL DEFAULT 'endpoints',
    state_json  TEXT NOT NULL,          -- filters, search, sort, columns
    created_at  TEXT NOT NULL,
    updated_at  TEXT,
    use_count   INTEGER NOT NULL DEFAULT 0,
    UNIQUE(project_id, view, name)
);

-- Ownership resolved at ingest, from config/ownership.yaml. Stored per run so a
-- later change to the register does not silently rewrite historical reports.
ALTER TABLE host_rollup ADD COLUMN owner         TEXT;
ALTER TABLE host_rollup ADD COLUMN business_unit TEXT;
ALTER TABLE host_rollup ADD COLUMN criticality   TEXT;
ALTER TABLE endpoints   ADD COLUMN owner         TEXT;
ALTER TABLE endpoints   ADD COLUMN business_unit TEXT;
ALTER TABLE endpoints   ADD COLUMN criticality   TEXT;

CREATE INDEX IF NOT EXISTS idx_ep_owner ON endpoints(run_id, owner);
