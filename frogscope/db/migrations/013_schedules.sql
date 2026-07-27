-- v2: per-project scheduled scanning, for servers that stay up 24/7.
--
-- A schedule stores exactly the same options shape a manual scan builds
-- (target_kind/targets/profile/flags/correlate) plus timing and an
-- unattended-approval policy, so the scheduler can hand it to the same
-- worker() execution path POST /api/scan already uses -- see
-- frogscope/api/routes.py's _SCANS/_SCAN_SLOT pattern.

CREATE TABLE IF NOT EXISTS schedules (
    id               INTEGER PRIMARY KEY,
    project_id       INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name             TEXT NOT NULL,
    target_kind      TEXT NOT NULL DEFAULT 'domain',
    targets_json     TEXT NOT NULL,
    profile          TEXT NOT NULL DEFAULT 'web',
    flags_json       TEXT,
    correlate_json   TEXT,
    subfinder        INTEGER NOT NULL DEFAULT 1,
    preset           TEXT NOT NULL DEFAULT 'daily',   -- hourly | daily | weekly
    time_of_day      TEXT,                             -- 'HH:MM', unused for hourly
    day_of_week      INTEGER,                           -- 0=Mon..6=Sun, weekly only
    -- Runs whose projected host count is at or under this cap auto-clear the
    -- approval gate (NeedsApproval) that a manual scan would otherwise pause
    -- on for a human click; runs over it are skipped and logged instead.
    max_hosts_cap    INTEGER NOT NULL DEFAULT 500,
    enabled          INTEGER NOT NULL DEFAULT 1,
    last_run_id      INTEGER REFERENCES runs(id) ON DELETE SET NULL,
    last_run_at      TEXT,
    last_skip_reason TEXT,
    next_run_at      TEXT,
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_schedules_project ON schedules(project_id);
CREATE INDEX IF NOT EXISTS idx_schedules_due      ON schedules(enabled, next_run_at);
