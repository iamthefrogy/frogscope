-- v2 correlation: scoring-visible and grid-filterable projections.
--
-- The scoring engine (scoring/engine.py score_record) takes a flat per-record
-- dict, and the endpoints grid can only filter real SQL columns declared in
-- config/columns.yaml — so a small set of scalars is denormalised onto
-- `endpoints`/`host_rollup` from the relational tables in 009/010, exactly
-- the same pattern `ip_cluster_size` already established in enrich.py.
--
-- `tls_version`, `cert_issuer`, `cert_not_after`, `cert_days_remaining`,
-- `jarm_hash` are RESERVED-BUT-EMPTY columns already in 001_init.sql — this
-- migration doesn't duplicate them, v2's ingest just starts filling them for
-- real from tlsx instead of httpx's `-tls-grab`.
--
-- No ASN columns here: asnmap/dnsx-asn/mapcidr's ASN input all require a
-- ProjectDiscovery API key, which this release deliberately does not depend
-- on (see config/cloud_ranges.yaml for the credential-free replacement used
-- by dangling_a_record/in_claimable_range).

ALTER TABLE endpoints ADD COLUMN ip_version                INTEGER;
ALTER TABLE endpoints ADD COLUMN cidr                       TEXT;
ALTER TABLE endpoints ADD COLUMN cidr_prefix_len            INTEGER;
ALTER TABLE endpoints ADD COLUMN ptr_host                   TEXT;
ALTER TABLE endpoints ADD COLUMN ptr_missing                INTEGER NOT NULL DEFAULT 0;
ALTER TABLE endpoints ADD COLUMN ptr_mismatch                INTEGER NOT NULL DEFAULT 0;
-- ip_cluster_size (001_init.sql) stays OUR-hostnames-only. These are the new,
-- separate foreign-name signal — see enrich.py's regression-trap comment:
-- folding PTR's foreign names into ip_cluster_size would trip concentration
-- rules on every Cloudflare IP, which has hundreds of PTR names.
ALTER TABLE endpoints ADD COLUMN ip_hostname_count          INTEGER NOT NULL DEFAULT 0;
ALTER TABLE endpoints ADD COLUMN ip_foreign_name_count      INTEGER NOT NULL DEFAULT 0;
ALTER TABLE endpoints ADD COLUMN ip_foreign_domain_count    INTEGER NOT NULL DEFAULT 0;
ALTER TABLE endpoints ADD COLUMN in_claimable_range         INTEGER NOT NULL DEFAULT 0;
ALTER TABLE endpoints ADD COLUMN claimable_provider         TEXT NOT NULL DEFAULT '';
ALTER TABLE endpoints ADD COLUMN dangling_a_record          INTEGER NOT NULL DEFAULT 0;

ALTER TABLE endpoints ADD COLUMN cert_sha256                TEXT;
ALTER TABLE endpoints ADD COLUMN cert_subject_cn             TEXT;
ALTER TABLE endpoints ADD COLUMN cert_issuer_org             TEXT;
ALTER TABLE endpoints ADD COLUMN cert_not_before             TEXT;
ALTER TABLE endpoints ADD COLUMN cert_age_days               INTEGER;
ALTER TABLE endpoints ADD COLUMN cert_expired                INTEGER NOT NULL DEFAULT 0;
ALTER TABLE endpoints ADD COLUMN cert_self_signed            INTEGER NOT NULL DEFAULT 0;
ALTER TABLE endpoints ADD COLUMN cert_mismatched             INTEGER NOT NULL DEFAULT 0;
ALTER TABLE endpoints ADD COLUMN cert_untrusted              INTEGER NOT NULL DEFAULT 0;
ALTER TABLE endpoints ADD COLUMN cert_revoked                INTEGER NOT NULL DEFAULT 0;
ALTER TABLE endpoints ADD COLUMN cert_wildcard               INTEGER NOT NULL DEFAULT 0;
ALTER TABLE endpoints ADD COLUMN cert_wildcard_scope         TEXT NOT NULL DEFAULT '';
ALTER TABLE endpoints ADD COLUMN cert_san_count              INTEGER NOT NULL DEFAULT 0;
ALTER TABLE endpoints ADD COLUMN cert_foreign_domain_count   INTEGER NOT NULL DEFAULT 0;
ALTER TABLE endpoints ADD COLUMN cert_host_count             INTEGER NOT NULL DEFAULT 0;
ALTER TABLE endpoints ADD COLUMN tls_cipher                  TEXT;
ALTER TABLE endpoints ADD COLUMN tls_cipher_grade            TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_ep_run_cidr   ON endpoints(run_id, cidr);
CREATE INDEX IF NOT EXISTS idx_ep_run_cert   ON endpoints(run_id, cert_sha256);
CREATE INDEX IF NOT EXISTS idx_ep_certexp    ON endpoints(run_id, cert_days_remaining);

ALTER TABLE host_rollup ADD COLUMN cidr_json                TEXT;
ALTER TABLE host_rollup ADD COLUMN ptr_json                  TEXT;
ALTER TABLE host_rollup ADD COLUMN cert_json                 TEXT;
ALTER TABLE host_rollup ADD COLUMN min_cert_days_remaining   INTEGER;
ALTER TABLE host_rollup ADD COLUMN worst_cert_state          TEXT NOT NULL DEFAULT '';
ALTER TABLE host_rollup ADD COLUMN max_ip_foreign_domains    INTEGER NOT NULL DEFAULT 0;
ALTER TABLE host_rollup ADD COLUMN in_claimable_range        INTEGER NOT NULL DEFAULT 0;
