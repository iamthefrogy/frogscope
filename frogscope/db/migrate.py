"""Ordered migration runner.

frogy_web's init_db() does:

    current = conn.execute("PRAGMA user_version").fetchone()[0]
    if current >= SCHEMA_VERSION:
        return

With SCHEMA_VERSION pinned at 1, every later edit to schema.sql is silently
never applied — the DB looks migrated and isn't. Here each numbered file is
applied exactly once, in order, inside a transaction, and user_version tracks
the highest applied number.
"""

from __future__ import annotations

import re
import sqlite3
from datetime import UTC
from pathlib import Path

MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"
_NAME_RE = re.compile(r"^(\d+)_.*\.sql$")


def discover() -> list[tuple[int, Path]]:
    found: list[tuple[int, Path]] = []
    for path in sorted(MIGRATIONS_DIR.glob("*.sql")):
        m = _NAME_RE.match(path.name)
        if not m:
            raise RuntimeError(
                f"migration filename must be NNN_description.sql, got {path.name!r}"
            )
        found.append((int(m.group(1)), path))

    numbers = [n for n, _ in found]
    dupes = {n for n in numbers if numbers.count(n) > 1}
    if dupes:
        raise RuntimeError(f"duplicate migration numbers: {sorted(dupes)}")
    return found


LEDGER_DDL = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    number     INTEGER PRIMARY KEY,
    filename   TEXT NOT NULL,
    applied_at TEXT NOT NULL
);
"""


def current_version(conn: sqlite3.Connection) -> int:
    return int(conn.execute("PRAGMA user_version").fetchone()[0])


def applied(conn: sqlite3.Connection) -> set[int]:
    """Which migrations have actually run.

    A ledger rather than a single high-water mark: `ALTER TABLE ADD COLUMN` is not
    idempotent in SQLite, so re-running a migration is not merely wasteful, it
    fails and leaves the schema half-changed. A max-version integer cannot
    express "3 ran but 2 did not", which is exactly the state a failed migration
    leaves behind.
    """
    conn.executescript(LEDGER_DDL)
    rows = conn.execute("SELECT number FROM schema_migrations").fetchall()
    known = {int(r[0]) for r in rows}
    if not known:
        # Adopting the ledger on a database migrated by the old integer scheme:
        # everything up to user_version is already in place.
        version = current_version(conn)
        if version:
            from datetime import datetime
            stamp = datetime.now(UTC).isoformat()
            for number, path in discover():
                if number <= version:
                    conn.execute(
                        "INSERT OR IGNORE INTO schema_migrations "
                        "(number, filename, applied_at) VALUES (?,?,?)",
                        (number, path.name, stamp))
                    known.add(number)
            conn.commit()
    return known


def migrate(conn: sqlite3.Connection, *, verbose: bool = False) -> list[int]:
    """Apply every migration not yet recorded in the ledger."""
    from datetime import datetime

    already = applied(conn)
    newly: list[int] = []

    for number, path in discover():
        if number in already:
            continue
        sql = path.read_text(encoding="utf-8")
        try:
            conn.executescript(sql)
            # executescript commits, so the ledger row is written afterwards.
            conn.execute(
                "INSERT OR REPLACE INTO schema_migrations "
                "(number, filename, applied_at) VALUES (?,?,?)",
                (number, path.name,
                 datetime.now(UTC).replace(microsecond=0).isoformat()))
            conn.execute(f"PRAGMA user_version = {number}")
            conn.commit()
        except sqlite3.Error:
            conn.rollback()
            raise
        newly.append(number)
        if verbose:
            print(f"applied migration {path.name}")

    return newly
