-- v2 correlation: domain<->IP<->CIDR, in both directions.
--
-- `endpoints.host_ip` has always been a single scalar with no reverse index —
-- "which hosts share this IP" is only reachable today as enrich.py's ad hoc
-- ip_cluster_size int. These tables make every direction a real, indexed
-- query instead of a derived count: domain->IP, IP->domain (reverse DNS),
-- CIDR->IP (expand), IP->CIDR (membership).
--
-- ip_sort_key is a fixed-width 32-hex-char zero-padded encoding of the
-- address as a 128-bit integer (v4 addresses mapped into the same space).
-- Lexicographic string ordering then equals numeric ordering for both
-- families in one column, so "which IPs fall inside this CIDR" is a single
-- indexed `BETWEEN` range scan, not a per-family branch or 65k materialised
-- rows for a /16.

CREATE TABLE IF NOT EXISTS ip_addresses (
    run_id                INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    asset_id              INTEGER REFERENCES assets(id) ON DELETE CASCADE,
    ip                    TEXT NOT NULL,
    ip_version            INTEGER NOT NULL,
    ip_sort_key           TEXT NOT NULL,
    is_private            INTEGER NOT NULL DEFAULT 0,
    ptr_count             INTEGER NOT NULL DEFAULT 0,
    ptr_primary           TEXT,
    ptr_json              TEXT,
    cidr                  TEXT,
    cdn                   INTEGER NOT NULL DEFAULT 0,
    cdn_name              TEXT,
    hostname_count        INTEGER NOT NULL DEFAULT 0,
    endpoint_count        INTEGER NOT NULL DEFAULT 0,
    foreign_name_count    INTEGER NOT NULL DEFAULT 0,
    foreign_domain_count  INTEGER NOT NULL DEFAULT 0,
    in_claimable_range    INTEGER NOT NULL DEFAULT 0,
    claimable_provider    TEXT,
    discovered_via        TEXT,
    extra_json            TEXT,
    PRIMARY KEY (run_id, ip)
);
CREATE INDEX IF NOT EXISTS idx_ip_run_cidr   ON ip_addresses(run_id, cidr);
CREATE INDEX IF NOT EXISTS idx_ip_run_sort   ON ip_addresses(run_id, ip_sort_key);
CREATE INDEX IF NOT EXISTS idx_ip_run_shared ON ip_addresses(run_id, foreign_domain_count DESC);
CREATE INDEX IF NOT EXISTS idx_ip_asset      ON ip_addresses(asset_id);

-- The domain<->IP edge, long format, one row per (name, record_type, value).
-- Long format (not a column per record type) so adding MX/TXT/NS later is a
-- new row shape, not a migration — the same reasoning as run_metrics.
CREATE TABLE IF NOT EXISTS dns_records (
    run_id       INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    record_type  TEXT NOT NULL,     -- A | AAAA | CNAME | PTR
    value        TEXT NOT NULL,     -- IP, or target name (lowercased, dot-stripped)
    ttl          INTEGER,
    chain_pos    INTEGER NOT NULL DEFAULT 0,
    source       TEXT NOT NULL DEFAULT 'dnsx',
    in_scope     INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (run_id, name, record_type, value)
);
-- Forward: domain -> IP/CNAME target.
CREATE INDEX IF NOT EXISTS idx_dns_fwd ON dns_records(run_id, name, record_type);
-- Reverse: IP/value -> every domain pointing at it. The index that has never
-- existed until now.
CREATE INDEX IF NOT EXISTS idx_dns_rev ON dns_records(run_id, value, record_type);

-- CIDR header. CIDR->IP membership is deliberately NOT materialised as one
-- row per address (a /16 is 65,536 rows, a /8 is 16 million) — each block
-- stores its integer bounds instead, so "which observed IPs are inside this
-- block" is one indexed range scan against ip_addresses.ip_sort_key.
CREATE TABLE IF NOT EXISTS cidr_blocks (
    run_id             INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    asset_id           INTEGER REFERENCES assets(id) ON DELETE CASCADE,
    cidr               TEXT NOT NULL,
    ip_version         INTEGER NOT NULL,
    prefix_len         INTEGER NOT NULL,
    ip_start_key       TEXT NOT NULL,
    ip_end_key         TEXT NOT NULL,
    ip_count           INTEGER NOT NULL,
    observed_ip_count  INTEGER NOT NULL DEFAULT 0,
    host_count         INTEGER NOT NULL DEFAULT 0,
    expanded           INTEGER NOT NULL DEFAULT 0,   -- enumerated address-by-address (mapcidr)
    was_scan_target    INTEGER NOT NULL DEFAULT 0,
    source             TEXT NOT NULL DEFAULT 'mapcidr',
    PRIMARY KEY (run_id, cidr)
);
CREATE INDEX IF NOT EXISTS idx_cidr_range ON cidr_blocks(run_id, ip_start_key, ip_end_key);
