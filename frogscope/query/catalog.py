"""The column catalogue.

Single source of truth for the grid, the export, the drawer field order, and —
critically — the SQL filter/sort whitelist. A column name that is not declared
in ``config/columns.yaml`` can never reach SQL.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..config import Config

# Columns held inside lists_json rather than as their own SQL column. Filtering
# these uses json_each, because a LIKE against a JSON blob quietly gives wrong
# answers (searching tech for "IIS" would also match "IIS" inside a URL).
LIST_BACKED = {
    "a": "$.a",
    "aaaa": "$.aaaa",
    "cname": "$.cname",
    "resolvers": "$.resolvers",
    "tech": "$.tech",
    "cpe_products": "$.cpe_products",
    "wp_plugins": "$.wp_plugins",
    "chain_providers": "$.chain_providers",
}


@dataclass(frozen=True)
class Column:
    key: str
    label: str
    group: str
    type: str
    filter: str
    width: int = 140
    align: str = "left"
    default_visible: bool = False
    sortable: bool = True
    description: str = ""
    exec_label: str = ""
    format: str = ""

    @property
    def is_list(self) -> bool:
        return self.key in LIST_BACKED

    @property
    def json_path(self) -> str | None:
        return LIST_BACKED.get(self.key)

    def as_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "label": self.label,
            "exec_label": self.exec_label or self.label,
            "group": self.group,
            "type": self.type,
            "filter": self.filter,
            "width": self.width,
            "align": self.align,
            "default_visible": self.default_visible,
            "sortable": self.sortable,
            "description": self.description,
            "format": self.format,
            "is_list": self.is_list,
        }


class Catalog:
    def __init__(self, cfg: Config):
        raw = cfg.columns
        self.groups: dict[str, dict] = raw.get("groups") or {}
        self.columns: dict[str, Column] = {}
        self.order: list[str] = []

        for entry in raw.get("columns") or []:
            col = Column(
                key=entry["key"],
                label=entry.get("label", entry["key"]),
                group=entry.get("group", "identity"),
                type=entry.get("type", "text"),
                filter=entry.get("filter", "search"),
                width=int(entry.get("width", 140)),
                align=entry.get("align", "left"),
                default_visible=bool(entry.get("default_visible")),
                sortable=bool(entry.get("sortable", True)),
                description=(entry.get("description") or "").strip(),
                exec_label=entry.get("exec_label", ""),
                format=entry.get("format", ""),
            )
            self.columns[col.key] = col
            self.order.append(col.key)

        self.presets: dict[str, Any] = raw.get("presets") or {}
        self.filter_presets: list[dict] = raw.get("filter_presets") or []

    def __contains__(self, key: str) -> bool:
        return key in self.columns

    def get(self, key: str) -> Column | None:
        return self.columns.get(key)

    def require(self, key: str) -> Column:
        col = self.columns.get(key)
        if col is None:
            raise KeyError(f"unknown column: {key!r}")
        return col

    def default_visible(self) -> list[str]:
        return [k for k in self.order if self.columns[k].default_visible]

    def sql_columns(self) -> list[str]:
        """Real SQL columns, i.e. excluding the list-backed ones."""
        return [k for k in self.order if not self.columns[k].is_list]

    def as_dict(self) -> dict[str, Any]:
        return {
            "groups": self.groups,
            "columns": [self.columns[k].as_dict() for k in self.order],
            "default_visible": self.default_visible(),
            "presets": self.presets,
            "filter_presets": self.filter_presets,
        }
