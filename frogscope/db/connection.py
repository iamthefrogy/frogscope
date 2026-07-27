"""SQLite connection helpers.

Adapted from frogy_web/db/connection.py (WAL, Row factory, foreign keys), with
the schema-version gate replaced — see migrate.py for why.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path


def connect(db_path: Path | str, *, readonly: bool = False) -> sqlite3.Connection:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    if readonly and path.exists():
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    else:
        conn = sqlite3.connect(str(path))

    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    if not readonly:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
    return conn


def check_features(conn: sqlite3.Connection) -> dict[str, bool]:
    """Verify the SQLite features the query layer depends on."""
    results: dict[str, bool] = {}
    probes = {
        "fts5": "CREATE VIRTUAL TABLE temp.__probe_fts USING fts5(a)",
        "json1": "SELECT 1 FROM json_each('[1]')",
        "window_functions": "SELECT row_number() OVER (ORDER BY 1)",
    }
    for name, sql in probes.items():
        try:
            conn.execute(sql)
            results[name] = True
        except sqlite3.Error:
            results[name] = False
    try:
        conn.execute("DROP TABLE IF EXISTS temp.__probe_fts")
    except sqlite3.Error:
        pass
    return results
