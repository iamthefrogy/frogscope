"""Persistence. Upsert patterns adapted from frogy_web/ingest/store.py."""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# Columns written to `endpoints`, in order. Kept explicit rather than derived
# from the record dict so an accidental new field cannot silently change the
# table's shape.
ENDPOINT_COLUMNS = (
    "run_id", "asset_id", "endpoint_key",
    "host", "host_display", "port", "scheme", "port_category",
    "env", "env_source", "zone", "registrable_domain", "host_depth",
    "response_class", "status_code", "status_class", "title", "title_class",
    "serves_content", "scan_artifact", "cf_alias_port", "waf_blocked",
    "content_type", "content_length", "words", "lines", "response_ms",
    "content_sig", "content_cluster_size",
    "final_url", "final_host", "redirect_offsite", "redirect_chain_len",
    "redirects_to_https", "no_tls_redirect",
    "auth_surface_type", "federated_auth", "remote_access_exposed", "mgmt_surface",
    "cdn_name", "cdn_type", "hosting_provider", "hosting_kind",
    "edge_provider", "edge_kind",
    "origin_exposed", "waf_protected", "no_waf", "behind_proxy",
    "azure_app_proxy", "origin_health", "cf_error_code",
    "third_party_dependency", "defence_layers", "unprotected",
    "host_ip", "cname_final", "ipv6_enabled", "dns_multi_a", "ip_cluster_size",
    "webserver", "webserver_family", "webserver_version", "version_disclosure",
    "tech_count", "tech_flat", "is_wordpress", "api_surface",
    "tls_version", "cert_issuer", "cert_not_after", "cert_days_remaining",
    "jarm_hash", "favicon_md5", "screenshot_path", "asn", "asn_org",
    "probe_count", "intra_run_inconsistent", "inconsistent_fields", "scheme_conflict",
    "owner", "business_unit", "criticality",
    "scanned_at", "lists_json", "raw_json", "extra_json",
    # Phase 2: risk and lifecycle
    "risk_score", "risk_band", "risk_excluded", "risk_confidence",
    "risk_coverage", "exposure", "hygiene", "sensitivity",
    "finding_count", "top_finding", "worst_severity", "risk_mitigated",
    "eol_count", "eol_worst_severity", "eol_years_past", "outdated_count",
    "vuln_family_count", "vuln_worst_severity",
    "takeover_grade", "takeover_provider", "takeover_confidence",
    # Passive product identification. Typed so "every exposed CI/CD console"
    # stays a server-side query.
    "panel_product", "panel_group", "panel_exposure", "panel_confidence",
    "panel_count", "is_default_page", "default_page_product",
    "disclosure_count", "disclosure_worst", "fingerprint_count",
    # v2: cross-asset correlation (dnsx / mapcidr / tlsx), denormalised from
    # ip_addresses/cidr_blocks/certificates for scoring and grid filtering.
    "ip_version", "cidr", "cidr_prefix_len",
    "ptr_host", "ptr_missing", "ptr_mismatch",
    "ip_hostname_count", "ip_foreign_name_count", "ip_foreign_domain_count",
    "in_claimable_range", "claimable_provider", "dangling_a_record",
    "cert_sha256", "cert_subject_cn", "cert_issuer_org", "cert_not_before",
    "cert_age_days", "cert_expired", "cert_self_signed", "cert_mismatched",
    "cert_untrusted", "cert_revoked", "cert_wildcard", "cert_wildcard_scope",
    "cert_san_count", "cert_foreign_domain_count", "cert_host_count",
    "tls_cipher", "tls_cipher_grade",
)

# Array fields bundled into lists_json, so the drawer and the token filters can
# reach them without one column per array.
LIST_FIELDS = (
    "a", "aaaa", "cname", "resolvers", "tech", "tech_names",
    "cpe_products", "wp_plugins", "wp_themes", "redirect_chain", "chain_providers",
    "eol_details", "outdated_details", "vuln_details", "takeover_evidence",
    # The full audit trail for each fingerprint match: which signal fired and
    # what was observed. A bare boolean cannot be argued with; this can.
    "fingerprint_hits", "fingerprint_skipped", "panel_products", "panel_groups",
    "disclosure_ids",
    # v2 correlation: full PTR list and full cert SAN list, so the drawer can
    # show everything even though only one representative lands in a scalar
    # column (ptr_host / cert_subject_cn).
    "ptr", "cert_sans",
)


def now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


# ── Projects ────────────────────────────────────────────────────────────────

def upsert_project(conn: sqlite3.Connection, slug: str, name: str | None = None) -> int:
    row = conn.execute("SELECT id FROM projects WHERE slug = ?", (slug,)).fetchone()
    if row:
        if name:
            conn.execute("UPDATE projects SET name = ? WHERE id = ?", (name, row["id"]))
        return int(row["id"])
    cur = conn.execute(
        "INSERT INTO projects (slug, name, created_at) VALUES (?,?,?)",
        (slug, name or slug, now_iso()),
    )
    return int(cur.lastrowid)


def list_projects(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT p.*, "
        " (SELECT COUNT(*) FROM runs r WHERE r.project_id = p.id) AS run_count "
        "FROM projects p ORDER BY p.name"
    ).fetchall()


# ── Runs ────────────────────────────────────────────────────────────────────

def find_duplicate(conn: sqlite3.Connection, project_id: int, raw_sha: str,
                   content_sha: str) -> sqlite3.Row | None:
    """Two layers: identical bytes, or identical normalised content.

    The second catches "same scan, re-exported with different column order",
    which a byte hash alone would miss.
    """
    row = conn.execute(
        "SELECT * FROM ingest_files WHERE raw_sha256 = ? AND project_id = ?",
        (raw_sha, project_id),
    ).fetchone()
    if row:
        return row
    return conn.execute(
        "SELECT * FROM ingest_files WHERE content_sha256 = ? AND project_id = ?",
        (content_sha, project_id),
    ).fetchone()


def insert_run(conn: sqlite3.Connection, project_id: int, meta: dict[str, Any]) -> int:
    cur = conn.execute(
        """INSERT INTO runs (
               project_id, run_key, label, run_kind, started_at, completed_at,
               scan_duration_s, ingested_at, source_file, raw_sha256,
               content_sha256, row_count, endpoint_count, host_count,
               config_hash, is_baseline, duplicate_of, incomplete,
               warnings_json, summary_json,
               rules_hash, rules_version, risk_summary_json
           ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            project_id,
            meta["run_key"],
            meta.get("label"),
            meta.get("run_kind", "adhoc"),
            meta.get("started_at"),
            meta.get("completed_at"),
            meta.get("scan_duration_s"),
            now_iso(),
            meta.get("source_file"),
            meta.get("raw_sha256"),
            meta.get("content_sha256"),
            meta.get("row_count"),
            meta.get("endpoint_count"),
            meta.get("host_count"),
            meta.get("config_hash"),
            1 if meta.get("is_baseline") else 0,
            meta.get("duplicate_of"),
            1 if meta.get("incomplete") else 0,
            json.dumps(meta.get("warnings") or []),
            json.dumps(meta.get("summary") or {}),
            meta.get("rules_hash"),
            meta.get("rules_version"),
            json.dumps(meta.get("risk_summary") or {}, default=str),
        ),
    )
    return int(cur.lastrowid)


def record_ingest_file(conn: sqlite3.Connection, project_id: int, run_id: int,
                       meta: dict[str, Any]) -> None:
    conn.execute(
        """INSERT OR REPLACE INTO ingest_files
             (raw_sha256, project_id, run_id, filename, bytes, row_count,
              content_sha256, ingested_at)
           VALUES (?,?,?,?,?,?,?,?)""",
        (
            meta["raw_sha256"], project_id, run_id, meta.get("source_file"),
            meta.get("byte_count"), meta.get("row_count"),
            meta.get("content_sha256"), now_iso(),
        ),
    )


def previous_run(conn: sqlite3.Connection, project_id: int,
                 before_run_id: int | None = None) -> sqlite3.Row | None:
    """Runs are ordered by when the scan happened, not when it was ingested,
    so backfilling an older CSV lands it correctly in the timeline."""
    rows = conn.execute(
        "SELECT * FROM runs WHERE project_id = ? AND duplicate_of IS NULL "
        "ORDER BY COALESCE(started_at,''), id",
        (project_id,),
    ).fetchall()
    if before_run_id is None:
        return rows[-1] if rows else None
    ids = [r["id"] for r in rows]
    if before_run_id not in ids:
        return rows[-1] if rows else None
    idx = ids.index(before_run_id)
    return rows[idx - 1] if idx > 0 else None


# ── Assets ──────────────────────────────────────────────────────────────────

def upsert_assets(conn: sqlite3.Connection, project_id: int, run_id: int,
                  kind: str, keys: list[tuple[str, str]]) -> dict[str, int]:
    """keys is [(key, label)]. Returns key -> asset_id."""
    out: dict[str, int] = {}
    for key, label in keys:
        conn.execute(
            """INSERT INTO assets
                 (project_id, kind, key, label, first_seen_run_id,
                  last_seen_run_id, runs_seen, current_status)
               VALUES (?,?,?,?,?,?,1,'active')
               ON CONFLICT(project_id, kind, key) DO UPDATE SET
                 last_seen_run_id = excluded.last_seen_run_id,
                 label            = excluded.label,
                 runs_seen        = assets.runs_seen + 1,
                 current_status   = 'active'""",
            (project_id, kind, key, label, run_id, run_id),
        )
        row = conn.execute(
            "SELECT id FROM assets WHERE project_id=? AND kind=? AND key=?",
            (project_id, kind, key),
        ).fetchone()
        out[key] = int(row["id"])
    return out


# ── Endpoints ───────────────────────────────────────────────────────────────

def _endpoint_row(rec: dict, run_id: int, asset_id: int | None) -> tuple:
    lists = {f: rec.get(f) or [] for f in LIST_FIELDS}
    lists["tech_versions"] = rec.get("tech_versions") or {}

    values: dict[str, Any] = {
        "run_id": run_id,
        "asset_id": asset_id,
        "lists_json": json.dumps(lists, default=str),
        "raw_json": json.dumps(rec.get("raw") or {}, default=str),
        "extra_json": json.dumps(rec.get("extra") or {}, default=str),
        "inconsistent_fields": json.dumps(rec.get("inconsistent_fields") or []),
    }
    for column in ENDPOINT_COLUMNS:
        if column in values:
            continue
        value = rec.get(column)
        values[column] = int(value) if isinstance(value, bool) else value
    return tuple(values[c] for c in ENDPOINT_COLUMNS)


def insert_endpoints(conn: sqlite3.Connection, run_id: int, records: list[dict],
                     asset_ids: dict[str, int]) -> int:
    placeholders = ",".join("?" for _ in ENDPOINT_COLUMNS)
    rows = [
        _endpoint_row(rec, run_id, asset_ids.get(rec["endpoint_key"]))
        for rec in records
    ]
    conn.executemany(
        f"INSERT OR REPLACE INTO endpoints ({','.join(ENDPOINT_COLUMNS)}) "
        f"VALUES ({placeholders})",
        rows,
    )

    conn.executemany(
        "INSERT INTO endpoints_fts "
        "(endpoint_key, host, title, tech_flat, webserver, cname_final, host_ip) "
        "VALUES (?,?,?,?,?,?,?)",
        [
            (
                f"{run_id}:{rec['endpoint_key']}",
                rec.get("host") or "",
                rec.get("title") or "",
                rec.get("tech_flat") or "",
                rec.get("webserver") or "",
                rec.get("cname_final") or "",
                rec.get("host_ip") or "",
            )
            for rec in records
        ],
    )
    return len(rows)


HOST_ROLLUP_COLUMNS = (
    "run_id", "asset_id", "host", "host_display", "env", "zone",
    "port_count", "serving_port_count", "real_port_count", "ports_json",
    "ip_json", "distinct_ip_count", "cname_json", "tech_json",
    "hosting_provider", "cdn_name", "origin_exposed", "waf_protected_count",
    "no_waf_count", "cdn_bypass_candidate",
    "has_auth_surface", "has_mgmt_surface", "origin_health", "service_diversity",
    "risk_score", "risk_band", "worst_endpoint", "finding_count", "breadth_bonus",
    "owner", "business_unit", "criticality",
    # v2 correlation
    "cidr_json", "ptr_json", "cert_json", "min_cert_days_remaining",
    "worst_cert_state", "max_ip_foreign_domains", "in_claimable_range",
)


def insert_host_rollups(conn: sqlite3.Connection, run_id: int, rollups: list[dict],
                        asset_ids: dict[str, int]) -> int:
    rows = []
    for r in rollups:
        rows.append((
            run_id, asset_ids.get(r["host"]), r["host"], r["host_display"],
            r["env"], r["zone"], r["port_count"], r["serving_port_count"],
            r["real_port_count"], json.dumps(r["ports"]), json.dumps(r["ips"]),
            r["distinct_ip_count"], json.dumps(r["cnames"]), json.dumps(r["techs"]),
            r["hosting_provider"], r["cdn_name"], int(bool(r["origin_exposed"])),
            r["waf_protected_count"], r["no_waf_count"],
            int(bool(r["cdn_bypass_candidate"])), int(bool(r["has_auth_surface"])),
            int(bool(r["has_mgmt_surface"])), r["origin_health"], r["service_diversity"],
            r.get("risk_score"), r.get("risk_band"), r.get("worst_endpoint"),
            r.get("finding_count", 0), r.get("breadth_bonus", 0),
            r.get("owner"), r.get("business_unit"), r.get("criticality"),
            json.dumps(r.get("cidrs") or []), json.dumps(r.get("ptr_names") or []),
            json.dumps(r.get("certs") or []), r.get("min_cert_days_remaining"),
            r.get("worst_cert_state", ""), r.get("max_ip_foreign_domains", 0),
            int(bool(r.get("in_claimable_range"))),
        ))
    placeholders = ",".join("?" for _ in HOST_ROLLUP_COLUMNS)
    conn.executemany(
        f"INSERT OR REPLACE INTO host_rollup ({','.join(HOST_ROLLUP_COLUMNS)}) "
        f"VALUES ({placeholders})",
        rows,
    )
    return len(rows)


# ── Network correlation (v2) ────────────────────────────────────────────────

IP_COLUMNS = (
    "run_id", "asset_id", "ip", "ip_version", "ip_sort_key", "is_private",
    "ptr_count", "ptr_primary", "ptr_json", "cidr", "cdn", "cdn_name",
    "hostname_count", "endpoint_count", "foreign_name_count",
    "foreign_domain_count", "in_claimable_range", "claimable_provider",
    "discovered_via", "extra_json",
)


def insert_ip_addresses(conn: sqlite3.Connection, run_id: int,
                        entries: list[dict], asset_ids: dict[str, int]) -> int:
    rows = [
        (
            run_id, asset_ids.get(e["ip"]), e["ip"], e["ip_version"],
            e["ip_sort_key"], int(bool(e.get("is_private"))),
            e.get("ptr_count", 0), e.get("ptr_primary"),
            json.dumps(e.get("ptr") or []), e.get("cidr"),
            int(bool(e.get("cdn"))), e.get("cdn_name"),
            e.get("hostname_count", 0), e.get("endpoint_count", 0),
            e.get("foreign_name_count", 0), e.get("foreign_domain_count", 0),
            int(bool(e.get("in_claimable_range"))), e.get("claimable_provider"),
            e.get("discovered_via"), json.dumps(e.get("extra") or {}, default=str),
        )
        for e in entries
    ]
    placeholders = ",".join("?" for _ in IP_COLUMNS)
    conn.executemany(
        f"INSERT OR REPLACE INTO ip_addresses ({','.join(IP_COLUMNS)}) "
        f"VALUES ({placeholders})",
        rows,
    )
    return len(rows)


def insert_dns_records(conn: sqlite3.Connection, run_id: int,
                       records: list[dict]) -> int:
    rows = [
        (run_id, r["name"], r["record_type"], r["value"], r.get("ttl"),
         r.get("chain_pos", 0), r.get("source", "dnsx"),
         int(bool(r.get("in_scope", True))))
        for r in records
    ]
    conn.executemany(
        "INSERT OR REPLACE INTO dns_records "
        "(run_id, name, record_type, value, ttl, chain_pos, source, in_scope) "
        "VALUES (?,?,?,?,?,?,?,?)",
        rows,
    )
    return len(rows)


def insert_cidr_blocks(conn: sqlite3.Connection, run_id: int,
                       blocks: list[dict], asset_ids: dict[str, int]) -> int:
    rows = [
        (run_id, asset_ids.get(b["cidr"]), b["cidr"], b["ip_version"],
         b["prefix_len"], b["ip_start_key"], b["ip_end_key"], b["ip_count"],
         b.get("observed_ip_count", 0), b.get("host_count", 0),
         int(bool(b.get("expanded"))), int(bool(b.get("was_scan_target"))),
         b.get("source", "mapcidr"))
        for b in blocks
    ]
    conn.executemany(
        "INSERT OR REPLACE INTO cidr_blocks "
        "(run_id, asset_id, cidr, ip_version, prefix_len, ip_start_key, "
        " ip_end_key, ip_count, observed_ip_count, host_count, expanded, "
        " was_scan_target, source) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        rows,
    )
    return len(rows)


# ── Certificates (v2) ────────────────────────────────────────────────────────

CERT_COLUMNS = (
    "run_id", "asset_id", "cert_sha256", "subject_cn", "subject_org",
    "subject_dn", "issuer_cn", "issuer_org", "issuer_dn", "serial",
    "not_before", "not_after", "days_remaining", "age_days", "validity_days",
    "expired", "self_signed", "mismatched", "revoked", "untrusted",
    "wildcard", "wildcard_scope", "san_count", "in_scope_name_count",
    "foreign_name_count", "foreign_domain_count", "new_name_count",
    "host_count", "ip_count", "tls_version", "cipher", "cipher_grade",
    "jarm_hash", "ja3_hash", "fingerprint_md5", "fingerprint_sha1",
    "source", "raw_json",
)
_CERT_BOOL_COLUMNS = ("expired", "self_signed", "mismatched", "revoked",
                      "untrusted", "wildcard")


def insert_certificates(conn: sqlite3.Connection, run_id: int,
                        certs: list[dict], asset_ids: dict[str, int]) -> int:
    rows = []
    for c in certs:
        values = {"run_id": run_id, "asset_id": asset_ids.get(c["cert_sha256"])}
        for column in CERT_COLUMNS:
            if column in values:
                continue
            if column == "raw_json":
                values[column] = json.dumps(c.get("raw") or {}, default=str)
            elif column in _CERT_BOOL_COLUMNS:
                values[column] = int(bool(c.get(column)))
            else:
                values[column] = c.get(column)
        rows.append(tuple(values[col] for col in CERT_COLUMNS))
    placeholders = ",".join("?" for _ in CERT_COLUMNS)
    conn.executemany(
        f"INSERT OR REPLACE INTO certificates ({','.join(CERT_COLUMNS)}) "
        f"VALUES ({placeholders})",
        rows,
    )
    return len(rows)


def insert_cert_names(conn: sqlite3.Connection, run_id: int,
                      names: list[dict]) -> int:
    rows = [
        (run_id, n["cert_sha256"], n["name"], n["name_kind"],
         int(bool(n.get("is_wildcard"))), n.get("registrable"),
         int(bool(n.get("in_scope"))), int(bool(n.get("discovered_new"))))
        for n in names
    ]
    conn.executemany(
        "INSERT OR REPLACE INTO cert_names "
        "(run_id, cert_sha256, name, name_kind, is_wildcard, registrable, "
        " in_scope, discovered_new) "
        "VALUES (?,?,?,?,?,?,?,?)",
        rows,
    )
    return len(rows)


def insert_cert_observations(conn: sqlite3.Connection, run_id: int,
                             obs: list[dict]) -> int:
    rows = [
        (run_id, o["cert_sha256"], o["host"], o.get("ip", ""), o["port"],
         o.get("endpoint_key"), o.get("sni"),
         int(bool(o.get("probe_status", True))), o.get("error"))
        for o in obs
    ]
    conn.executemany(
        "INSERT OR REPLACE INTO cert_observations "
        "(run_id, cert_sha256, host, ip, port, endpoint_key, sni, "
        " probe_status, error) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        rows,
    )
    return len(rows)


def insert_run_collectors(conn: sqlite3.Connection, run_id: int,
                          collectors: list[dict]) -> int:
    rows = [
        (run_id, c["tool"], c.get("version"), int(bool(c.get("ran"))),
         c.get("exit_code"), c.get("skip_reason"), c.get("inputs", 0),
         c.get("outputs", 0), c.get("duration_s"))
        for c in collectors
    ]
    conn.executemany(
        "INSERT OR REPLACE INTO run_collectors "
        "(run_id, tool, version, ran, exit_code, skip_reason, inputs, "
        " outputs, duration_s) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        rows,
    )
    return len(rows)


def insert_column_census(conn: sqlite3.Connection, run_id: int,
                         census: list[dict]) -> None:
    conn.executemany(
        "INSERT OR REPLACE INTO run_columns "
        "(run_id, column_name, non_empty, total, fill_pct, sample) "
        "VALUES (?,?,?,?,?,?)",
        [
            (run_id, c["column_name"], c["non_empty"], c["total"],
             c["fill_pct"], c["sample"])
            for c in census
        ],
    )


def delete_run(conn: sqlite3.Connection, run_id: int) -> None:
    conn.execute(
        "DELETE FROM endpoints_fts WHERE endpoint_key LIKE ?", (f"{run_id}:%",)
    )
    conn.execute("DELETE FROM runs WHERE id = ?", (run_id,))


# ── Deleting things ─────────────────────────────────────────────────────────
#
# Every delete below is irreversible, so each one first reports exactly what it
# is about to remove. A caller that cannot show the user a count has no business
# asking them to confirm.

def project_stats(conn: sqlite3.Connection, project_id: int) -> dict:
    """What a project holds. Used to tell the user what they are about to lose."""
    one = lambda sql, args=(): conn.execute(sql, args).fetchone()[0]  # noqa: E731
    runs = [r["run_key"] for r in conn.execute(
        "SELECT run_key FROM runs WHERE project_id = ? "
        "ORDER BY COALESCE(started_at, ''), id", (project_id,))]
    return {
        "runs": len(runs),
        "run_keys": runs,
        "endpoints": one("SELECT COUNT(*) FROM endpoints e JOIN runs r "
                         "ON r.id = e.run_id WHERE r.project_id = ?",
                         (project_id,)),
        "assets": one("SELECT COUNT(*) FROM assets WHERE project_id = ?",
                      (project_id,)),
        "findings": one("SELECT COUNT(*) FROM findings WHERE project_id = ?",
                        (project_id,)),
        "changes": one("SELECT COUNT(*) FROM changes WHERE project_id = ?",
                       (project_id,)),
        "saved_views": one("SELECT COUNT(*) FROM saved_views WHERE project_id = ?",
                           (project_id,)),
        "ip_addresses": one(
            "SELECT COUNT(*) FROM ip_addresses i JOIN runs r ON r.id = i.run_id "
            "WHERE r.project_id = ?", (project_id,)),
        "certificates": one(
            "SELECT COUNT(*) FROM certificates c JOIN runs r ON r.id = c.run_id "
            "WHERE r.project_id = ?", (project_id,)),
        "schedules": one("SELECT COUNT(*) FROM schedules WHERE project_id = ?",
                         (project_id,)),
    }


# Tables keyed directly on project_id. Everything else hangs off `runs` and goes
# with it via ON DELETE CASCADE.
_PROJECT_TABLES = ("asset_attr_history", "asset_presence", "changes",
                   "findings", "ingest_files", "notifications", "saved_views",
                   "assets", "schedules")


def delete_project(conn: sqlite3.Connection, project_id: int, *,
                   raw_dir=None) -> dict:
    """Remove a project and everything belonging to it.

    Rows are deleted explicitly rather than left to cascade alone, because
    `endpoints_fts` is a plain FTS5 table with no foreign key to cascade through —
    a cascade would drop the endpoints and leave their search index behind, so the
    global search box would keep returning hosts that no longer exist.
    """
    stats = project_stats(conn, project_id)

    for run_key in stats["run_keys"]:
        if raw_dir is not None:
            archive = Path(raw_dir) / f"{run_key}.csv.gz"
            archive.unlink(missing_ok=True)

    for row in conn.execute("SELECT id FROM runs WHERE project_id = ?",
                            (project_id,)).fetchall():
        conn.execute("DELETE FROM endpoints_fts WHERE endpoint_key LIKE ?",
                     (f"{row['id']}:%",))

    conn.execute("DELETE FROM runs WHERE project_id = ?", (project_id,))
    for table in _PROJECT_TABLES:
        conn.execute(f"DELETE FROM {table} WHERE project_id = ?", (project_id,))
    conn.execute("DELETE FROM projects WHERE id = ?", (project_id,))
    conn.commit()
    return stats


def reset_all(conn: sqlite3.Connection, *, raw_dir=None) -> dict:
    """Empty the store completely, keeping the schema.

    Schema and migration ledger survive on purpose: the alternative is deleting
    the database file, which the running server still holds open.
    """
    counts = {
        "projects": conn.execute("SELECT COUNT(*) FROM projects").fetchone()[0],
        "runs": conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0],
        "endpoints": conn.execute("SELECT COUNT(*) FROM endpoints").fetchone()[0],
        "raw_archives": 0,
    }

    if raw_dir is not None and Path(raw_dir).is_dir():
        for archive in Path(raw_dir).glob("*.csv.gz"):
            archive.unlink(missing_ok=True)
            counts["raw_archives"] += 1

    # Everything except the schema ledger. `endpoints_fts` is listed explicitly
    # for the same reason as above, and the shadow tables it owns are left to it.
    tables = [r["name"] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' "
        "AND name NOT LIKE 'sqlite_%' AND name != 'schema_migrations' "
        "AND name NOT LIKE 'endpoints_fts_%'")]
    for table in tables:
        conn.execute(f"DELETE FROM {table}")
    conn.commit()
    conn.execute("VACUUM")
    return counts


SCORE_COLUMNS = (
    "run_id", "endpoint_key", "asset_id", "score", "raw_score", "band",
    "exposure", "hygiene", "sensitivity", "excluded", "excluded_by",
    "floored_from", "worst_severity", "mitigated", "confidence", "coverage",
    "contributions_json", "modifiers_json", "skipped_json",
)


def insert_scores(conn: sqlite3.Connection, run_id: int,
                  scored: list, asset_ids: dict[str, int]) -> int:
    """Persist the full scoring trace, so "why 72?" always has an exact answer."""
    from dataclasses import asdict

    rows = []
    for record, result in scored:
        rows.append((
            run_id, record["endpoint_key"], asset_ids.get(record["endpoint_key"]),
            result.score, result.raw_score, result.band,
            result.buckets.get("exposure", 0), result.buckets.get("hygiene", 0),
            result.buckets.get("sensitivity", 0),
            int(bool(result.excluded)), result.excluded_by, result.floored_from,
            result.worst_severity, int(bool(result.mitigated)),
            result.confidence, result.coverage,
            json.dumps([asdict(c) for c in result.contributions], default=str),
            json.dumps([asdict(m) for m in result.modifiers], default=str),
            json.dumps(result.skipped, default=str),
        ))
    placeholders = ",".join("?" for _ in SCORE_COLUMNS)
    conn.executemany(
        f"INSERT OR REPLACE INTO asset_scores ({','.join(SCORE_COLUMNS)}) "
        f"VALUES ({placeholders})",
        rows,
    )
    return len(rows)


# ── Scheduled scanning (v2) ─────────────────────────────────────────────────

def insert_schedule(conn: sqlite3.Connection, project_id: int, data: dict) -> int:
    now = now_iso()
    cur = conn.execute(
        "INSERT INTO schedules "
        "(project_id, name, target_kind, targets_json, profile, flags_json, "
        " correlate_json, subfinder, preset, time_of_day, day_of_week, "
        " max_hosts_cap, enabled, next_run_at, created_at, updated_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (project_id, data["name"], data["target_kind"], data["targets_json"],
         data["profile"], data["flags_json"], data["correlate_json"],
         int(bool(data.get("subfinder", True))), data["preset"],
         data.get("time_of_day"), data.get("day_of_week"),
         int(data["max_hosts_cap"]), int(bool(data.get("enabled", True))),
         data["next_run_at"], now, now),
    )
    return int(cur.lastrowid)


def list_schedules(conn: sqlite3.Connection, project_id: int) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM schedules WHERE project_id = ? ORDER BY name",
        (project_id,),
    ).fetchall()


def get_schedule(conn: sqlite3.Connection, schedule_id: int) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT * FROM schedules WHERE id = ?", (schedule_id,)
    ).fetchone()


def update_schedule(conn: sqlite3.Connection, schedule_id: int, fields: dict) -> None:
    """`fields` maps column name -> new value. Only ever called with columns
    the API route itself has already whitelisted — this executes whatever
    keys it is given, so it must never see a caller-supplied column name."""
    if not fields:
        return
    fields = {**fields, "updated_at": now_iso()}
    set_clause = ", ".join(f"{key} = ?" for key in fields)
    conn.execute(f"UPDATE schedules SET {set_clause} WHERE id = ?",
                (*fields.values(), schedule_id))


def delete_schedule(conn: sqlite3.Connection, schedule_id: int) -> None:
    conn.execute("DELETE FROM schedules WHERE id = ?", (schedule_id,))
