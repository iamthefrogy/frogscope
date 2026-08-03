"""Facet counts with cross-filtering.

Each facet's counts are computed against every *other* active filter but not its
own. Without that exclusion a facet zeroes itself out the moment you click a
value in it — you pick "cloudflare" and every other CDN drops to 0, so you can
no longer see what else is available or switch selection. Excluding the facet's
own filter is what makes the sidebar usable.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from .catalog import Catalog
from .filters import compile_filters, search_clause

# Facets are only meaningful for bounded value sets.
MAX_DISTINCT = 60


def _base_where(run_id: int, filters: dict[str, Any], search: str,
                catalog: Catalog, exclude: str | None = None
                ) -> tuple[str, list[Any]]:
    subset = {k: v for k, v in (filters or {}).items() if k != exclude}
    clause, params = compile_filters(subset, catalog)

    where = ["run_id = ?"]
    all_params: list[Any] = [run_id]
    if clause:
        where.append(clause)
        all_params.extend(params)
    if search:
        sclause, sparams = search_clause(search, catalog)
        if sclause:
            where.append(sclause)
            all_params.extend(sparams)
    return " AND ".join(where), all_params


def compute(conn: sqlite3.Connection, run_id: int, catalog: Catalog,
            filters: dict[str, Any] | None = None, search: str = "",
            fields: list[str] | None = None) -> dict[str, list[dict]]:
    filters = filters or {}
    candidates = fields or [
        k for k in catalog.order
        if catalog.columns[k].filter in ("multiselect", "bool")
    ]

    out: dict[str, list[dict]] = {}
    for key in candidates:
        col = catalog.get(key)
        if col is None or col.is_list:
            continue

        where, params = _base_where(run_id, filters, search, catalog, exclude=key)
        rows = conn.execute(
            f'SELECT "{key}" AS value, COUNT(*) AS n FROM endpoints '
            f"WHERE {where} GROUP BY 1 ORDER BY n DESC, 1 LIMIT {MAX_DISTINCT + 1}",
            params,
        ).fetchall()

        if len(rows) > MAX_DISTINCT:
            continue  # too many distinct values to be a useful facet

        values: list[dict] = []
        for row in rows:
            raw = row["value"]
            if col.type == "bool":
                label = "Yes" if raw in (1, "1", True) else "No"
                value: Any = bool(raw)
            elif raw in (None, ""):
                label = "(empty)"
                value = ""
            else:
                label = str(raw)
                value = raw
            values.append({"value": value, "label": label, "count": row["n"]})

        if values:
            out[key] = values

    # List-backed columns need their own pass through json_each.
    for key, col in catalog.columns.items():
        if not col.is_list or (fields and key not in fields):
            continue
        where, params = _base_where(run_id, filters, search, catalog, exclude=key)
        rows = conn.execute(
            f"SELECT je.value AS value, COUNT(*) AS n FROM endpoints, "
            f"json_each(endpoints.lists_json, ?) je "
            f"WHERE {where} GROUP BY 1 ORDER BY n DESC, 1 LIMIT {MAX_DISTINCT}",
            [col.json_path] + params,
        ).fetchall()
        values = [
            {"value": r["value"], "label": str(r["value"]), "count": r["n"]}
            for r in rows if r["value"] not in (None, "")
        ]
        if values:
            out[key] = values

    return out


def visible_columns(conn: sqlite3.Connection, run_id: int) -> dict[str, float]:
    """Source-column fill rates for this run, so the UI can hide empty columns."""
    rows = conn.execute(
        "SELECT column_name, fill_pct FROM run_columns WHERE run_id = ?",
        (run_id,),
    ).fetchall()
    return {r["column_name"]: r["fill_pct"] for r in rows}


def query_endpoints(conn: sqlite3.Connection, run_id: int, catalog: Catalog, *,
                    filters: dict[str, Any] | None = None, search: str = "",
                    sort: str | None = None, page: int = 1,
                    page_size: int = 100, columns: list[str] | None = None,
                    full: bool = False,
                    ) -> dict[str, Any]:
    from .filters import compile_sort

    where, params = _base_where(run_id, filters or {}, search, catalog)
    order = compile_sort(sort, catalog)

    total = conn.execute(
        f"SELECT COUNT(*) AS n FROM endpoints WHERE {where}", params
    ).fetchone()["n"]

    if full:
        # Bulk export: no page cap, grab every matching row in one go.
        page = 1
        page_size = max(1, total)
    else:
        page = max(1, int(page))
        page_size = max(1, min(5000, int(page_size)))
    offset = (page - 1) * page_size

    select = list(dict.fromkeys(
        ["endpoint_key", "asset_id"]
        + [c for c in (columns or catalog.default_visible())
           if c in catalog and not catalog.columns[c].is_list]
    ))
    needs_lists = any(
        catalog.columns[c].is_list for c in (columns or catalog.default_visible())
        if c in catalog
    )
    if needs_lists:
        select.append("lists_json")

    quoted = ",".join(f'"{c}"' for c in select)
    rows = conn.execute(
        f"SELECT {quoted} FROM endpoints WHERE {where} "
        f"ORDER BY {order} LIMIT ? OFFSET ?",
        params + [page_size, offset],
    ).fetchall()

    out_rows: list[dict] = []
    for row in rows:
        record = dict(row)
        lists_json = record.pop("lists_json", None)
        if lists_json:
            try:
                record.update(json.loads(lists_json))
            except json.JSONDecodeError:
                pass
        out_rows.append(record)

    return {
        "rows": out_rows,
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": max(1, (total + page_size - 1) // page_size),
    }
