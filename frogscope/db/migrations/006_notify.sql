-- Notification ledger.
--
-- The point of this table is that an alert fires ONCE. Without it, re-running
-- `notify`, re-ingesting a run, or a later scan re-observing the same finding
-- would each re-post it, and a channel that cries wolf gets muted — which costs
-- you the one genuinely urgent alert.

CREATE TABLE IF NOT EXISTS notifications (
    id          INTEGER PRIMARY KEY,
    project_id  INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    run_id      INTEGER REFERENCES runs(id) ON DELETE SET NULL,
    target      TEXT NOT NULL,
    dedup_key   TEXT NOT NULL,
    trigger     TEXT NOT NULL,
    severity    TEXT,
    summary     TEXT,
    status      TEXT NOT NULL DEFAULT 'sent',   -- sent / failed / suppressed / dry_run
    error       TEXT,
    sent_at     TEXT,
    -- Per target, not global: adding a new channel must be able to receive an
    -- item the old channel already got, otherwise a new integration starts
    -- silent and looks broken.
    UNIQUE(project_id, target, dedup_key)
);

CREATE INDEX IF NOT EXISTS idx_notif_run ON notifications(run_id);
CREATE INDEX IF NOT EXISTS idx_notif_status ON notifications(project_id, status);
