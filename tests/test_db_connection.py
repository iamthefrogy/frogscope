"""frogscope.db.connection: pragmas applied on every connect()."""

from __future__ import annotations

from frogscope.db.connection import connect


def test_connect_sets_busy_timeout(tmp_path):
    conn = connect(tmp_path / "frogscope.db")
    try:
        (value,) = conn.execute("PRAGMA busy_timeout").fetchone()
        assert value == 8000
    finally:
        conn.close()


def test_connect_readonly_still_sets_busy_timeout(tmp_path):
    db_path = tmp_path / "frogscope.db"
    connect(db_path).close()  # create the file first — readonly requires it

    conn = connect(db_path, readonly=True)
    try:
        (value,) = conn.execute("PRAGMA busy_timeout").fetchone()
        assert value == 8000
    finally:
        conn.close()
