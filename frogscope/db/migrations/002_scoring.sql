-- Phase 2: risk scoring and findings.

-- Risk columns on the wide endpoints table, so the grid can filter and sort by
-- score and band server-side.
ALTER TABLE endpoints ADD COLUMN risk_score       INTEGER;
ALTER TABLE endpoints ADD COLUMN risk_band        TEXT;
ALTER TABLE endpoints ADD COLUMN risk_excluded    INTEGER NOT NULL DEFAULT 0;
ALTER TABLE endpoints ADD COLUMN risk_confidence  TEXT;
ALTER TABLE endpoints ADD COLUMN risk_coverage    REAL;
ALTER TABLE endpoints ADD COLUMN exposure         INTEGER;
ALTER TABLE endpoints ADD COLUMN hygiene          INTEGER;
ALTER TABLE endpoints ADD COLUMN sensitivity      INTEGER;
ALTER TABLE endpoints ADD COLUMN finding_count    INTEGER NOT NULL DEFAULT 0;
ALTER TABLE endpoints ADD COLUMN top_finding      TEXT;
-- The band answers "how risky is this endpoint overall"; worst_severity
-- answers "how bad is its worst single issue". Both are needed: a
-- WAF-protected host running end-of-life software has a modest band and a
-- critical worst_severity, and reporting only one of those misleads.
ALTER TABLE endpoints ADD COLUMN worst_severity   TEXT;
ALTER TABLE endpoints ADD COLUMN risk_mitigated   INTEGER NOT NULL DEFAULT 0;

-- Lifecycle and takeover fields, derived for scoring.
ALTER TABLE endpoints ADD COLUMN eol_count            INTEGER NOT NULL DEFAULT 0;
ALTER TABLE endpoints ADD COLUMN eol_worst_severity   TEXT;
ALTER TABLE endpoints ADD COLUMN eol_years_past       REAL;
ALTER TABLE endpoints ADD COLUMN outdated_count       INTEGER NOT NULL DEFAULT 0;
ALTER TABLE endpoints ADD COLUMN vuln_family_count    INTEGER NOT NULL DEFAULT 0;
ALTER TABLE endpoints ADD COLUMN vuln_worst_severity  TEXT;
ALTER TABLE endpoints ADD COLUMN takeover_grade       TEXT;
ALTER TABLE endpoints ADD COLUMN takeover_provider    TEXT;
ALTER TABLE endpoints ADD COLUMN takeover_confidence  TEXT;

CREATE INDEX IF NOT EXISTS idx_ep_run_score ON endpoints(run_id, risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_ep_run_band  ON endpoints(run_id, risk_band);

-- The full scoring trace, kept per endpoint per run. This is what lets the UI
-- answer "why 72?" down to the individual signal, and what makes a weight change
-- auditable after the fact.
CREATE TABLE IF NOT EXISTS asset_scores (
    run_id            INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    endpoint_key      TEXT NOT NULL,
    asset_id          INTEGER REFERENCES assets(id) ON DELETE CASCADE,
    score             INTEGER NOT NULL DEFAULT 0,
    raw_score         INTEGER NOT NULL DEFAULT 0,
    band              TEXT,
    exposure          INTEGER NOT NULL DEFAULT 0,
    hygiene           INTEGER NOT NULL DEFAULT 0,
    sensitivity       INTEGER NOT NULL DEFAULT 0,
    excluded          INTEGER NOT NULL DEFAULT 0,
    excluded_by       TEXT,
    floored_from      TEXT,
    worst_severity    TEXT,
    mitigated         INTEGER NOT NULL DEFAULT 0,
    confidence        TEXT,
    coverage          REAL,
    contributions_json TEXT,   -- every contribution, with evidence
    modifiers_json    TEXT,
    skipped_json      TEXT,    -- rules skipped for want of data, and why
    PRIMARY KEY (run_id, endpoint_key)
);

-- Host-level rollup of scores.
ALTER TABLE host_rollup ADD COLUMN risk_score     INTEGER;
ALTER TABLE host_rollup ADD COLUMN risk_band      TEXT;
ALTER TABLE host_rollup ADD COLUMN worst_endpoint TEXT;
ALTER TABLE host_rollup ADD COLUMN finding_count  INTEGER NOT NULL DEFAULT 0;
ALTER TABLE host_rollup ADD COLUMN breadth_bonus  INTEGER NOT NULL DEFAULT 0;

-- Findings, deduplicated per (rule, asset) across runs so the same problem keeps
-- one identity and its own history.
CREATE TABLE IF NOT EXISTS findings (
    id                INTEGER PRIMARY KEY,
    project_id        INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    run_id            INTEGER REFERENCES runs(id) ON DELETE SET NULL,
    rule_id           TEXT NOT NULL,
    severity          TEXT NOT NULL DEFAULT 'info',
    confidence        TEXT NOT NULL DEFAULT 'confirmed',
    title             TEXT NOT NULL,
    asset_kind        TEXT NOT NULL DEFAULT 'host',
    asset_key         TEXT NOT NULL,
    detail_json       TEXT,
    dedup_key         TEXT NOT NULL,
    status            TEXT NOT NULL DEFAULT 'open',   -- open / ack / resolved
    ack_by            TEXT,
    ack_at            TEXT,
    ack_note          TEXT,
    first_seen_run_id INTEGER REFERENCES runs(id) ON DELETE SET NULL,
    last_seen_run_id  INTEGER REFERENCES runs(id) ON DELETE SET NULL,
    resolved_run_id   INTEGER REFERENCES runs(id) ON DELETE SET NULL,
    created_at        TEXT,
    updated_at        TEXT,
    UNIQUE(project_id, dedup_key)
);
CREATE INDEX IF NOT EXISTS idx_findings_status   ON findings(project_id, status);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(project_id, severity);
CREATE INDEX IF NOT EXISTS idx_findings_rule     ON findings(project_id, rule_id);
CREATE INDEX IF NOT EXISTS idx_findings_asset    ON findings(project_id, asset_key);

-- The scoring configuration in force for each run. If this changes between runs,
-- a score delta may be a re-scoring rather than a real-world change, and the UI
-- must be able to say so rather than reporting a phantom improvement.
ALTER TABLE runs ADD COLUMN rules_hash    TEXT;
ALTER TABLE runs ADD COLUMN rules_version INTEGER;
ALTER TABLE runs ADD COLUMN risk_summary_json TEXT;
