"""Request-scoped database and config access. Pattern from frogy_web/api/_db.py."""

from __future__ import annotations

import sqlite3

from flask import current_app, g

from ..config import Config
from ..db.connection import connect
from ..query.catalog import Catalog


def get_config() -> Config:
    return current_app.config["FROGSCOPE_CONFIG"]


def get_catalog() -> Catalog:
    catalog = current_app.config.get("FROGSCOPE_CATALOG")
    if catalog is None:
        catalog = Catalog(get_config())
        current_app.config["FROGSCOPE_CATALOG"] = catalog
    return catalog


def get_db() -> sqlite3.Connection:
    if "_db" not in g:
        g._db = connect(get_config().db_path)
    return g._db


def close_db(_exc: BaseException | None = None) -> None:
    conn = g.pop("_db", None)
    if conn is not None:
        conn.close()


def resolve_run(conn: sqlite3.Connection, run: str | int | None,
                project: str | None = None) -> sqlite3.Row | None:
    """Accept a numeric id, a run_key, or 'latest'."""
    if run in (None, "", "latest"):
        sql = (
            "SELECT r.* FROM runs r JOIN projects p ON p.id = r.project_id "
            "WHERE r.duplicate_of IS NULL"
        )
        params: list = []
        if project:
            sql += " AND p.slug = ?"
            params.append(project)
        # DESC on started_at as well as id. Ordering ascending by scan time and
        # only descending by id returns the EARLIEST run, which is invisible
        # while there is a single run and wrong the moment there are two.
        sql += " ORDER BY COALESCE(r.started_at,'') DESC, r.id DESC LIMIT 1"
        return conn.execute(sql, params).fetchone()

    text = str(run)
    if text.isdigit():
        return conn.execute("SELECT * FROM runs WHERE id = ?", (int(text),)).fetchone()
    return conn.execute("SELECT * FROM runs WHERE run_key = ?", (text,)).fetchone()
