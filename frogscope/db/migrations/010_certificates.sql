-- v2 correlation: TLS certificates, from tlsx.
--
-- Cert identity is the leaf SHA-256 fingerprint (tlsx `-hash=sha256`'s
-- fingerprint_hash.sha256) rather than issuer+serial: self-signed certs can
-- collide on issuer+serial, a fingerprint cannot.
--
-- Every misconfig boolean (expired/self_signed/mismatched/revoked/untrusted)
-- is confirmed from real tlsx output to be OMITTED from JSON when false, not
-- present as false (Go `omitempty`) — see tests/fixtures/correlation/README.md.
-- ingest/correlate.py must treat key-absence as false, never guess a default.

CREATE TABLE IF NOT EXISTS certificates (
    run_id               INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    asset_id             INTEGER REFERENCES assets(id) ON DELETE CASCADE,
    cert_sha256          TEXT NOT NULL,
    subject_cn           TEXT,
    subject_org          TEXT,
    subject_dn           TEXT,
    issuer_cn            TEXT,
    issuer_org           TEXT,
    issuer_dn            TEXT,
    serial               TEXT,
    not_before           TEXT,
    not_after            TEXT,
    days_remaining       INTEGER,
    age_days             INTEGER,
    validity_days        INTEGER,
    expired              INTEGER NOT NULL DEFAULT 0,
    self_signed          INTEGER NOT NULL DEFAULT 0,
    mismatched           INTEGER NOT NULL DEFAULT 0,
    revoked              INTEGER NOT NULL DEFAULT 0,
    untrusted            INTEGER NOT NULL DEFAULT 0,
    wildcard             INTEGER NOT NULL DEFAULT 0,
    wildcard_scope       TEXT,
    san_count            INTEGER NOT NULL DEFAULT 0,
    in_scope_name_count  INTEGER NOT NULL DEFAULT 0,
    foreign_name_count   INTEGER NOT NULL DEFAULT 0,
    foreign_domain_count INTEGER NOT NULL DEFAULT 0,
    new_name_count       INTEGER NOT NULL DEFAULT 0,
    host_count           INTEGER NOT NULL DEFAULT 0,
    ip_count             INTEGER NOT NULL DEFAULT 0,
    tls_version          TEXT,
    cipher               TEXT,
    cipher_grade         TEXT,     -- secure | weak | insecure
    jarm_hash            TEXT,
    ja3_hash             TEXT,
    fingerprint_md5      TEXT,
    fingerprint_sha1     TEXT,
    source               TEXT NOT NULL DEFAULT 'tlsx',
    raw_json             TEXT,
    PRIMARY KEY (run_id, cert_sha256)
);
CREATE INDEX IF NOT EXISTS idx_cert_expiry  ON certificates(run_id, days_remaining);
CREATE INDEX IF NOT EXISTS idx_cert_bad     ON certificates(run_id, expired, self_signed, mismatched);
CREATE INDEX IF NOT EXISTS idx_cert_foreign ON certificates(run_id, foreign_domain_count DESC);

-- The cert<->domain edge, via SAN. Answers both "which domains does this
-- cert cover" and "which certs mention this name" from one table.
CREATE TABLE IF NOT EXISTS cert_names (
    run_id         INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    cert_sha256    TEXT NOT NULL,
    name           TEXT NOT NULL,
    name_kind      TEXT NOT NULL,     -- cn | san_dns
    is_wildcard    INTEGER NOT NULL DEFAULT 0,
    registrable    TEXT,
    in_scope       INTEGER NOT NULL DEFAULT 0,
    -- A name this cert asserts that no prior run of this project has ever
    -- seen. This is the "N domains you didn't know about" number.
    discovered_new INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (run_id, cert_sha256, name)
);
CREATE INDEX IF NOT EXISTS idx_certnames_name ON cert_names(run_id, name);
CREATE INDEX IF NOT EXISTS idx_certnames_new  ON cert_names(run_id, discovered_new);
CREATE INDEX IF NOT EXISTS idx_certnames_reg  ON cert_names(run_id, registrable);

-- Which host/ip/port actually presented this cert. Answers "one key on 40
-- hosts" and "this host presents someone else's certificate" (bare-IP grabs
-- of a shared vhost's default cert, per the fixture README's bare-IP caveat).
CREATE TABLE IF NOT EXISTS cert_observations (
    run_id       INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    cert_sha256  TEXT NOT NULL,
    host         TEXT NOT NULL,
    ip           TEXT NOT NULL DEFAULT '',
    port         INTEGER NOT NULL,
    endpoint_key TEXT,
    sni          TEXT,
    probe_status INTEGER NOT NULL DEFAULT 1,
    error        TEXT,
    PRIMARY KEY (run_id, cert_sha256, host, ip, port)
);
CREATE INDEX IF NOT EXISTS idx_certobs_host ON cert_observations(run_id, host);
CREATE INDEX IF NOT EXISTS idx_certobs_ip   ON cert_observations(run_id, ip);
