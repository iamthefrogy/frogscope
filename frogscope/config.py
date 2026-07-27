"""Layered configuration loading.

Everything tunable lives in ``config/*.yaml`` so weights, keywords, and
classification rules can be argued about and changed without a code edit. The
config content is hashed into each run, so a later scoring change is
distinguishable from a real-world change.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent


def _resolve_config_dir() -> Path:
    """Find `config/`, checking the places it can legitimately be.

    `config/` is meant to be EDITED — weights, keywords, and ownership are all
    tunable — so it lives beside the checkout rather than inside the package. That
    means it has to be looked up rather than assumed:

    1. `$FROGSCOPE_CONFIG_DIR`, for running several tuned configs against one
       install.
    2. `./config` in the working directory, so a per-target config can sit next to
       that target's data.
    3. the checkout the package was imported from.

    A wrong answer here is worse than no answer: silently falling back to defaults
    would mean somebody's tuned weights were quietly ignored, so an unresolvable
    config raises instead.
    """
    env = os.getenv("FROGSCOPE_CONFIG_DIR")
    if env:
        return Path(env)
    for candidate in (Path.cwd() / "config", REPO_ROOT / "config"):
        if (candidate / "ports.yaml").exists():
            return candidate
    # Nothing found. Return the checkout path so the error names somewhere real.
    return REPO_ROOT / "config"


def _resolve_data_dir() -> Path:
    env = os.getenv("FROGSCOPE_DATA_DIR")
    if env:
        return Path(env)
    # Beside the config that is actually in use, so data and the rules that
    # produced it stay together.
    return _resolve_config_dir().parent / "data"


DEFAULT_CONFIG_DIR = _resolve_config_dir()
DEFAULT_DATA_DIR = _resolve_data_dir()

_FILES = ("ports", "classify", "columns", "diff", "ownership")


class ConfigError(RuntimeError):
    """Raised when configuration is missing or structurally invalid."""


@dataclass
class Config:
    ports: dict[str, Any]
    classify: dict[str, Any]
    columns: dict[str, Any]
    diff: dict[str, Any]
    ownership: dict[str, Any]
    config_dir: Path
    data_dir: Path
    config_hash: str = ""

    # Derived lookups, built once in __post_init__ so hot paths never re-parse.
    cf_alias_ports: set[int] = field(default_factory=set)
    tls_only_ports: set[int] = field(default_factory=set)
    standard_ports: set[int] = field(default_factory=set)
    port_category: dict[int, str] = field(default_factory=dict)
    title_patterns: list[tuple[str, str, re.Pattern, bool]] = field(default_factory=list)
    env_lookup: dict[str, str] = field(default_factory=dict)
    env_precedence: dict[str, int] = field(default_factory=dict)
    auth_type_patterns: list[tuple[str, re.Pattern]] = field(default_factory=list)
    cname_providers: list[dict[str, Any]] = field(default_factory=list)
    idp_hosts: tuple[str, ...] = ()
    alias_port_providers: frozenset[str] = frozenset()
    origin_error_providers: frozenset[str] = frozenset()
    multi_label_tlds: tuple[str, ...] = ()
    ownership_rules: list[tuple[re.Pattern, dict[str, Any]]] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.cf_alias_ports = set(self.ports.get("cf_alias_http", [])) | set(
            self.ports.get("cf_alias_https", [])
        )
        self.tls_only_ports = set(self.ports.get("tls_only", []))
        # Named in config rather than hardcoded, so a different proxy with the
        # same behaviour can be added without touching Python.
        self.alias_port_providers = frozenset(
            str(n).lower() for n in
            (self.ports.get("alias_port_providers") or ["cloudflare"]))
        self.origin_error_providers = frozenset(
            str(n).lower() for n in
            (self.classify.get("origin_error_providers") or ["cloudflare"]))
        self.standard_ports = set(self.ports.get("standard_web", []))
        for name, spec in (self.ports.get("categories") or {}).items():
            for p in spec.get("ports", []):
                self.port_category.setdefault(int(p), name)

        for entry in self.classify.get("title_classes") or []:
            self.title_patterns.append(
                (
                    entry["class"],
                    entry.get("label", entry["class"]),
                    re.compile(entry["match"], re.I),
                    bool(entry.get("artifact")),
                )
            )

        env_cfg = self.classify.get("env") or {}
        # Shipped defaults first, then the site's own naming on top. Keeping them
        # in separate blocks is what lets the defaults stay industry-general: one
        # organisation's internal shorthand would mis-classify every other estate
        # that happens to use the same string.
        merged: dict[str, list[str]] = {}
        for source in (env_cfg.get("keywords") or {},
                       env_cfg.get("custom_keywords") or {}):
            for env_name, keywords in source.items():
                merged.setdefault(env_name, []).extend(keywords or [])

        for env_name, keywords in merged.items():
            for kw in keywords:
                # Longest keyword wins, so only overwrite with a longer token.
                prev = self.env_lookup.get(kw)
                if prev is None or len(env_name) > len(prev):
                    self.env_lookup[kw.lower()] = env_name
        self.env_precedence = {
            name: idx for idx, name in enumerate(env_cfg.get("precedence") or [])
        }

        auth_cfg = self.classify.get("auth") or {}
        for entry in auth_cfg.get("types") or []:
            self.auth_type_patterns.append((entry["type"], re.compile(entry["match"], re.I)))
        self.idp_hosts = tuple(h.lower() for h in auth_cfg.get("idp_hosts") or [])

        # Longest suffix first so `cdn.cloudflare.net` beats `cloudflare.net`.
        self.cname_providers = sorted(
            self.classify.get("cname_providers") or [],
            key=lambda e: len(e["suffix"]),
            reverse=True,
        )
        self.multi_label_tlds = tuple(self.classify.get("multi_label_tlds") or [])

        # Ownership is not observable from a scan, so this starts empty and the
        # UI says so rather than presenting an invented split as fact.
        for entry in self.ownership.get("rules") or []:
            try:
                pattern = re.compile(entry["match"], re.I)
            except (re.error, KeyError):
                continue
            self.ownership_rules.append((pattern, {
                "owner": entry.get("owner", ""),
                "business_unit": entry.get("business_unit", ""),
                "criticality": entry.get("criticality", ""),
                "contact": entry.get("contact", ""),
            }))

    # ── Convenience accessors ────────────────────────────────────────────────

    @property
    def env_default(self) -> str:
        return (self.classify.get("env") or {}).get("default", "unclassified")

    @property
    def nonprod_envs(self) -> set[str]:
        return set(self.classify.get("nonprod") or [])

    @property
    def cf_error_codes(self) -> dict[int, dict[str, Any]]:
        raw = self.classify.get("cf_error_codes") or {}
        return {int(k): v for k, v in raw.items()}

    @property
    def error_titles(self) -> set[str]:
        return set(self.classify.get("error_titles") or [])

    @property
    def remote_access_auth_types(self) -> set[str]:
        return set((self.classify.get("auth") or {}).get("remote_access_types") or [])

    @property
    def remote_access_cpe(self) -> set[str]:
        return set((self.classify.get("auth") or {}).get("remote_access_cpe") or [])

    @property
    def cdn_provider_kinds(self) -> set[str]:
        return set(self.classify.get("cdn_provider_kinds") or [])

    def owner_for(self, host: str) -> dict[str, str]:
        """First matching ownership rule, or empty. Order matters, so specific
        patterns must sit above general ones in the file."""
        for pattern, meta in self.ownership_rules:
            if pattern.search(host):
                return meta
        return {"owner": "", "business_unit": "", "criticality": "", "contact": ""}

    @property
    def has_ownership(self) -> bool:
        return bool(self.ownership_rules)

    @property
    def ownership_note(self) -> str:
        return (self.ownership.get("unconfigured_note") or "").strip()

    @property
    def db_path(self) -> Path:
        return Path(os.getenv("FROGSCOPE_DB", self.data_dir / "frogscope.sqlite"))

    @property
    def raw_dir(self) -> Path:
        return self.data_dir / "raw"


def load_config(config_dir: Path | str | None = None,
                data_dir: Path | str | None = None) -> Config:
    cdir = Path(config_dir) if config_dir else DEFAULT_CONFIG_DIR
    ddir = Path(data_dir) if data_dir else DEFAULT_DATA_DIR
    if not cdir.is_dir():
        raise ConfigError(
            f"config directory not found: {cdir}\n"
            f"Frogscope reads its rules from a `config/` directory. Run it from a "
            f"checkout, or point at one with FROGSCOPE_CONFIG_DIR=/path/to/config."
        )

    loaded: dict[str, Any] = {}
    digest = hashlib.sha256()
    for name in _FILES:
        path = cdir / f"{name}.yaml"
        if not path.exists():
            raise ConfigError(f"missing required config file: {path}")
        text = path.read_text(encoding="utf-8")
        digest.update(f"{name}\0".encode())
        digest.update(text.encode("utf-8"))
        try:
            loaded[name] = yaml.safe_load(text) or {}
        except yaml.YAMLError as exc:
            raise ConfigError(f"{path} is not valid YAML: {exc}") from exc

    cfg = Config(
        ports=loaded["ports"],
        classify=loaded["classify"],
        columns=loaded["columns"],
        diff=loaded["diff"],
        ownership=loaded["ownership"],
        config_dir=cdir,
        data_dir=ddir,
        config_hash=digest.hexdigest()[:16],
    )
    validate_config(cfg)
    return cfg


def validate_config(cfg: Config) -> list[str]:
    """Fail loudly on structural problems rather than mis-classifying quietly."""
    problems: list[str] = []

    seen: dict[int, str] = {}
    for name, spec in (cfg.ports.get("categories") or {}).items():
        for p in spec.get("ports", []):
            if p in seen:
                problems.append(
                    f"port {p} appears in two categories: {seen[p]} and {name}"
                )
            seen[p] = name

    if not cfg.classify.get("title_classes"):
        problems.append("classify.yaml defines no title_classes")

    for entry in cfg.classify.get("title_classes") or []:
        if "class" not in entry or "match" not in entry:
            problems.append(f"title_classes entry missing class/match: {entry!r}")

    cols = cfg.columns.get("columns") or []
    if not cols:
        problems.append("columns.yaml defines no columns")
    keys = [c["key"] for c in cols]
    dupes = {k for k in keys if keys.count(k) > 1}
    if dupes:
        problems.append(f"duplicate column keys: {sorted(dupes)}")

    known_groups = set(cfg.columns.get("groups") or {})
    for c in cols:
        if c.get("group") not in known_groups:
            problems.append(f"column {c['key']!r} has unknown group {c.get('group')!r}")

    keyset = set(keys)
    for pname, preset in (cfg.columns.get("presets") or {}).items():
        unknown = [c for c in preset.get("columns", []) if c not in keyset]
        if unknown:
            problems.append(f"preset {pname!r} references unknown columns: {unknown}")

    if problems:
        raise ConfigError(
            "configuration is invalid:\n  - " + "\n  - ".join(problems)
        )
    return problems


def config_fingerprint(cfg: Config) -> str:
    """Stable short hash recorded on each run, for re-scoring detection."""
    return cfg.config_hash


def dump_config(cfg: Config) -> str:
    return json.dumps(
        {
            "config_hash": cfg.config_hash,
            "config_dir": str(cfg.config_dir),
            "data_dir": str(cfg.data_dir),
            "db_path": str(cfg.db_path),
            "columns": len(cfg.columns.get("columns") or []),
            "title_classes": len(cfg.title_patterns),
            "cf_alias_ports": sorted(cfg.cf_alias_ports),
            "port_categories": sorted(set(cfg.port_category.values())),
        },
        indent=2,
    )
