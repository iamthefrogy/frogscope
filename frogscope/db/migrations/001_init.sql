-- Initial schema.
--
-- Adapted from frogy_web/db/schema.sql, whose projects/runs/assets/
-- asset_attributes/findings/changes spine is the right per-run snapshot and
-- diff model. Two deliberate departures:
--
--   1. A wide, typed, indexed `endpoints` table. frogy keeps everything in an
--      opaque attr_json blob, which cannot be filtered or sorted server-side —
--      fatal for "every column has a filter" across 50+ columns. raw_json still
--      carries every source column for the drawer, so nothing is lost.
--   2. Ordered migrations instead of a single schema.sql behind a version gate,
--      because that gate silently skips later edits.

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS projects (
    id          INTEGER PRIMARY KEY,
    slug        TEXT NOT NULL UNIQUE,
    name        TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    notes       TEXT
);

CREATE TABLE IF NOT EXISTS runs (
    id              INTEGER PRIMARY KEY,
    project_id      INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    run_key         TEXT NOT NULL,          -- run-YYYYMMDDTHHMMZ__label__hash8
    label           TEXT,
    run_kind        TEXT DEFAULT 'adhoc',   -- baseline/weekly/monthly/adhoc
    started_at      TEXT,                   -- min(timestamp) from the CSV itself
    completed_at    TEXT,                   -- max(timestamp)
    scan_duration_s REAL,
    ingested_at     TEXT NOT NULL,
    source_file     TEXT,
    raw_sha256      TEXT,
    content_sha256  TEXT,                   -- over normalised records; order-independent
    row_count       INTEGER,
    endpoint_count  INTEGER,
    host_count      INTEGER,
    config_hash     TEXT,
    is_baseline     INTEGER NOT NULL DEFAULT 0,
    duplicate_of    INTEGER REFERENCES runs(id) ON DELETE SET NULL,
    incomplete      INTEGER NOT NULL DEFAULT 0,
    warnings_json   TEXT,
    summary_json    TEXT,
    UNIQUE(project_id, run_key)
);
CREATE INDEX IF NOT EXISTS idx_runs_project ON runs(project_id, started_at);

-- Canonical cross-run identity. kind+key is stable, so run-over-run diffing is
-- a set operation on this table.
CREATE TABLE IF NOT EXISTS assets (
    id                INTEGER PRIMARY KEY,
    project_id        INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    kind              TEXT NOT NULL,        -- endpoint | host
    key               TEXT NOT NULL,        -- host_lower[:port]
    label             TEXT,
    first_seen_run_id INTEGER REFERENCES runs(id) ON DELETE SET NULL,
    last_seen_run_id  INTEGER REFERENCES runs(id) ON DELETE SET NULL,
    runs_seen         INTEGER NOT NULL DEFAULT 0,
    absent_runs       INTEGER NOT NULL DEFAULT 0,
    flap_count        INTEGER NOT NULL DEFAULT 0,
    current_status    TEXT NOT NULL DEFAULT 'active',   -- active | removed
    UNIQUE(project_id, kind, key)
);
CREATE INDEX IF NOT EXISTS idx_assets_project_kind ON assets(project_id, kind);
CREATE INDEX IF NOT EXISTS idx_assets_status ON assets(project_id, current_status);

-- The wide, filterable projection. One row per endpoint per run.
CREATE TABLE IF NOT EXISTS endpoints (
    run_id                 INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    asset_id               INTEGER REFERENCES assets(id) ON DELETE CASCADE,
    endpoint_key           TEXT NOT NULL,

    -- identity
    host                   TEXT NOT NULL,
    host_display           TEXT,
    port                   INTEGER NOT NULL,
    scheme                 TEXT,
    port_category          TEXT,
    env                    TEXT,
    env_source             TEXT,
    zone                   TEXT,
    registrable_domain     TEXT,
    host_depth             INTEGER,

    -- response
    response_class         TEXT,
    status_code            INTEGER,
    status_class           TEXT,
    title                  TEXT,
    title_class            TEXT,
    serves_content         INTEGER,
    scan_artifact          INTEGER,
    cf_alias_port          INTEGER,
    waf_blocked            INTEGER,
    content_type           TEXT,
    content_length         INTEGER,
    words                  INTEGER,
    lines                  INTEGER,
    response_ms            REAL,
    content_sig            TEXT,
    content_cluster_size   INTEGER,

    -- redirect / auth
    final_url              TEXT,
    final_host             TEXT,
    redirect_offsite       INTEGER,
    redirect_chain_len     INTEGER,
    redirects_to_https     INTEGER,
    no_tls_redirect        INTEGER,
    auth_surface_type      TEXT,
    federated_auth         INTEGER,
    remote_access_exposed  INTEGER,
    mgmt_surface           INTEGER,

    -- edge & hosting
    cdn_name               TEXT,
    cdn_type               TEXT,
    hosting_provider       TEXT,
    hosting_kind           TEXT,
    edge_provider          TEXT,
    edge_kind              TEXT,
    origin_exposed         INTEGER,
    waf_protected          INTEGER,
    no_waf                 INTEGER,
    behind_proxy           INTEGER,
    azure_app_proxy        INTEGER,
    origin_health          TEXT,
    cf_error_code          INTEGER,
    third_party_dependency TEXT,
    defence_layers         INTEGER,
    unprotected            INTEGER,

    -- dns
    host_ip                TEXT,
    cname_final            TEXT,
    ipv6_enabled           INTEGER,
    dns_multi_a            INTEGER,
    ip_cluster_size        INTEGER,

    -- technology
    webserver              TEXT,
    webserver_family       TEXT,
    webserver_version      TEXT,
    version_disclosure     INTEGER,
    tech_count             INTEGER,
    tech_flat              TEXT,             -- lowercased, space-joined, for search
    is_wordpress           INTEGER,
    api_surface            INTEGER,

    -- reserved: populated only when httpx is run with richer flags
    tls_version            TEXT,
    cert_issuer            TEXT,
    cert_not_after         TEXT,
    cert_days_remaining    INTEGER,
    jarm_hash              TEXT,
    favicon_md5            TEXT,
    screenshot_path        TEXT,
    asn                    TEXT,
    asn_org                TEXT,

    -- data quality
    probe_count            INTEGER NOT NULL DEFAULT 1,
    intra_run_inconsistent INTEGER NOT NULL DEFAULT 0,
    inconsistent_fields    TEXT,
    scheme_conflict        INTEGER NOT NULL DEFAULT 0,

    -- provenance and blobs
    scanned_at             TEXT,
    lists_json             TEXT,             -- a/aaaa/cname/tech/cpe_products/wp_plugins/resolvers
    raw_json               TEXT,             -- every source column, verbatim
    extra_json             TEXT,             -- unknown future httpx columns

    PRIMARY KEY (run_id, endpoint_key)
);
CREATE INDEX IF NOT EXISTS idx_ep_run_host     ON endpoints(run_id, host);
CREATE INDEX IF NOT EXISTS idx_ep_run_env      ON endpoints(run_id, env);
CREATE INDEX IF NOT EXISTS idx_ep_run_rclass   ON endpoints(run_id, response_class);
CREATE INDEX IF NOT EXISTS idx_ep_run_port     ON endpoints(run_id, port);
CREATE INDEX IF NOT EXISTS idx_ep_run_ip       ON endpoints(run_id, host_ip);
CREATE INDEX IF NOT EXISTS idx_ep_run_provider ON endpoints(run_id, hosting_provider);
CREATE INDEX IF NOT EXISTS idx_ep_asset        ON endpoints(asset_id);

-- Full-text search over the fields a human actually types into a search box.
CREATE VIRTUAL TABLE IF NOT EXISTS endpoints_fts USING fts5(
    endpoint_key, host, title, tech_flat, webserver, cname_final, host_ip,
    tokenize = 'unicode61 remove_diacritics 2'
);

-- Host-grain rollup.
CREATE TABLE IF NOT EXISTS host_rollup (
    run_id              INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    asset_id            INTEGER REFERENCES assets(id) ON DELETE CASCADE,
    host                TEXT NOT NULL,
    host_display        TEXT,
    env                 TEXT,
    zone                TEXT,
    port_count          INTEGER,
    serving_port_count  INTEGER,
    real_port_count     INTEGER,   -- excludes Cloudflare aliases and artefacts
    ports_json          TEXT,
    ip_json             TEXT,
    distinct_ip_count   INTEGER,
    cname_json          TEXT,
    tech_json           TEXT,
    hosting_provider    TEXT,
    cdn_name            TEXT,
    origin_exposed      INTEGER,
    waf_protected_count INTEGER,
    no_waf_count        INTEGER,
    cdn_bypass_candidate INTEGER,
    has_auth_surface    INTEGER,
    has_mgmt_surface    INTEGER,
    origin_health       TEXT,
    service_diversity   INTEGER,
    PRIMARY KEY (run_id, host)
);

-- Per-column fill census. Drives the UI's auto-hide of empty columns and the
-- "which httpx flags would help" recommendation.
CREATE TABLE IF NOT EXISTS run_columns (
    run_id      INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    column_name TEXT NOT NULL,
    non_empty   INTEGER NOT NULL,
    total       INTEGER NOT NULL,
    fill_pct    REAL NOT NULL,
    sample      TEXT,
    PRIMARY KEY (run_id, column_name)
);

-- Idempotency ledger: same bytes, or same normalised content, already ingested?
CREATE TABLE IF NOT EXISTS ingest_files (
    raw_sha256     TEXT PRIMARY KEY,
    project_id     INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    run_id         INTEGER REFERENCES runs(id) ON DELETE CASCADE,
    filename       TEXT,
    bytes          INTEGER,
    row_count      INTEGER,
    content_sha256 TEXT,
    ingested_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ingest_content ON ingest_files(content_sha256);
