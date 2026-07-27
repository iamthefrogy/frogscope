"""Compile a typed filter spec into parameterised SQL.

Semantics deliberately match the existing frogy report (header.html:5871):
**AND across columns, OR within a single column's value list**, and free-text
search ORs across cells. That is what users already expect.

Two improvements over that implementation: it is typed (so `risk_score > 60` is
expressible, which a DOM-text filter cannot do), and it runs in SQL over the
whole run rather than over the currently-rendered page.

Every column name is resolved through the catalogue before it can reach SQL, so
an unknown or hostile name raises instead of being interpolated.
"""

from __future__ import annotations

from typing import Any

from .catalog import Catalog, Column

TRUEISH = {"true", "1", "yes", "y", "on"}
FALSEISH = {"false", "0", "no", "n", "off"}


class FilterError(ValueError):
    pass


def _coerce(col: Column, value: Any) -> Any:
    if value is None:
        return None
    if col.type in ("int",):
        try:
            return int(float(str(value)))
        except ValueError as exc:
            raise FilterError(f"{col.key}: {value!r} is not a number") from exc
    if col.type in ("float",):
        try:
            return float(str(value))
        except ValueError as exc:
            raise FilterError(f"{col.key}: {value!r} is not a number") from exc
    if col.type == "bool":
        text = str(value).strip().lower()
        if text in TRUEISH:
            return 1
        if text in FALSEISH:
            return 0
        raise FilterError(f"{col.key}: {value!r} is not a boolean")
    return str(value)


def _scalar_clause(col: Column, values: list[Any]) -> tuple[str, list[Any]]:
    """OR within one column. Supports '!x' negation and text operators."""
    include: list[Any] = []
    exclude: list[Any] = []
    extra_sql: list[str] = []
    params: list[Any] = []

    for raw in values:
        text = str(raw)

        if text.startswith("!"):
            exclude.append(_coerce(col, text[1:]))
            continue

        if col.type in ("text", "host", "url") and len(text) > 1:
            if text.startswith("~"):                     # contains
                extra_sql.append(f'"{col.key}" LIKE ?')
                params.append(f"%{text[1:]}%")
                continue
            if text.startswith("="):                     # exact
                include.append(_coerce(col, text[1:]))
                continue

        if raw is None or text == "":
            extra_sql.append(f'("{col.key}" IS NULL OR "{col.key}" = \'\')')
            continue

        include.append(_coerce(col, raw))

    clauses: list[str] = []
    if include:
        placeholders = ",".join("?" for _ in include)
        clauses.append(f'"{col.key}" IN ({placeholders})')
        params = include + params
    if extra_sql:
        clauses.extend(extra_sql)

    sql = " OR ".join(f"({c})" for c in clauses) if clauses else ""

    if exclude:
        placeholders = ",".join("?" for _ in exclude)
        neg = f'("{col.key}" IS NULL OR "{col.key}" NOT IN ({placeholders}))'
        params = params + exclude
        sql = f"({sql}) AND {neg}" if sql else neg

    return sql, params


def _range_clause(col: Column, spec: dict) -> tuple[str, list[Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    if spec.get("min") not in (None, ""):
        clauses.append(f'"{col.key}" >= ?')
        params.append(_coerce(col, spec["min"]))
    if spec.get("max") not in (None, ""):
        clauses.append(f'"{col.key}" <= ?')
        params.append(_coerce(col, spec["max"]))
    return " AND ".join(clauses), params


def _list_clause(col: Column, spec: Any) -> tuple[str, list[Any]]:
    """Token filtering over a JSON array with any / all / none semantics.

    A text match against the raw JSON blob would be the wrong tool: it ignores
    element boundaries and would silently return misleading results.
    """
    if isinstance(spec, dict):
        tokens = spec.get("values") or []
        mode = (spec.get("mode") or "any").lower()
    else:
        tokens = spec if isinstance(spec, list) else [spec]
        mode = "any"

    tokens = [str(t) for t in tokens if str(t).strip()]
    if not tokens:
        return "", []

    path = col.json_path
    exists = (
        "EXISTS (SELECT 1 FROM json_each(endpoints.lists_json, ?) je "
        "WHERE lower(je.value) = lower(?))"
    )

    if mode == "all":
        parts = [exists] * len(tokens)
        params: list[Any] = []
        for token in tokens:
            params.extend([path, token])
        return " AND ".join(parts), params

    parts = [exists] * len(tokens)
    params = []
    for token in tokens:
        params.extend([path, token])
    joined = " OR ".join(parts)

    if mode == "none":
        return f"NOT ({joined})", params
    return f"({joined})", params


def compile_filters(filters: dict[str, Any], catalog: Catalog
                    ) -> tuple[str, list[Any]]:
    """Return (sql_fragment, params). AND across columns."""
    if not filters:
        return "", []

    clauses: list[str] = []
    params: list[Any] = []

    for key, spec in filters.items():
        if spec in (None, "", [], {}):
            continue
        col = catalog.get(key)
        if col is None:
            raise FilterError(f"unknown column in filter: {key!r}")

        if col.is_list:
            sql, p = _list_clause(col, spec)
        elif isinstance(spec, dict) and ("min" in spec or "max" in spec):
            sql, p = _range_clause(col, spec)
        else:
            values = spec if isinstance(spec, list) else [spec]
            sql, p = _scalar_clause(col, values)

        if sql:
            clauses.append(f"({sql})")
            params.extend(p)

    return " AND ".join(clauses), params


def compile_sort(sort: str | None, catalog: Catalog,
                 default: str = "endpoint_key") -> str:
    """Accepts 'col' or '-col' for descending. Multi-key via comma."""
    if not sort:
        return f'"{default}" ASC'

    parts: list[str] = []
    for token in str(sort).split(","):
        token = token.strip()
        if not token:
            continue
        direction = "DESC" if token.startswith("-") else "ASC"
        key = token.lstrip("-+")
        col = catalog.get(key)
        if col is None:
            raise FilterError(f"unknown sort column: {key!r}")
        if col.is_list:
            raise FilterError(f"cannot sort by list column: {key!r}")
        if not col.sortable:
            raise FilterError(f"column is not sortable: {key!r}")
        parts.append(f'"{key}" {direction}')

    parts.append(f'"{default}" ASC')     # stable tiebreak
    return ", ".join(parts)


def search_clause(term: str, catalog: Catalog) -> tuple[str, list[Any]]:
    """Free-text search: OR across the fields a human would type into a box."""
    term = (term or "").strip()
    if not term:
        return "", []
    fields = [
        f for f in ("endpoint_key", "host_display", "title", "tech_flat",
                    "webserver", "cname_final", "host_ip", "final_url",
                    "hosting_provider", "zone")
        if f in catalog
    ]
    clause = " OR ".join(f'"{f}" LIKE ?' for f in fields)
    return f"({clause})", [f"%{term}%"] * len(fields)
