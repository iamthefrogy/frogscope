"""Flask application factory."""

from __future__ import annotations

import secrets
from pathlib import Path

from flask import Flask, jsonify, render_template, request

from .api._db import close_db
from .api.routes import api
from .auth import get_or_create_key
from .config import Config, load_config
from .db.connection import connect
from .db.migrate import migrate
from .query.catalog import Catalog

HERE = Path(__file__).resolve().parent

# Never gated: the SPA shell and its assets have to load far enough to render
# the key-entry screen itself, and the healthcheck predates any notion of a
# key. `/api/auth/verify` is the one API route that must be reachable WITH
# no key yet, since checking a submitted key is the whole point of it.
_UNGATED_PATHS = ("/", "/healthz", "/api/auth/verify")
_UNGATED_PREFIXES = ("/static/",)


def create_app(cfg: Config | None = None) -> Flask:
    cfg = cfg or load_config()

    app = Flask(
        __name__,
        template_folder=str(HERE / "templates"),
        static_folder=str(HERE / "static"),
        static_url_path="/static",
    )
    app.config["FROGSCOPE_CONFIG"] = cfg
    app.config["FROGSCOPE_CATALOG"] = Catalog(cfg)
    app.config["MAX_CONTENT_LENGTH"] = 512 * 1024 * 1024
    app.config["JSON_SORT_KEYS"] = False

    conn = connect(cfg.db_path)
    try:
        migrate(conn)
    finally:
        conn.close()

    auth_key, just_created = get_or_create_key(cfg.data_dir)
    app.config["FROGSCOPE_AUTH_KEY"] = auth_key
    if just_created:
        # The one place this is ever printed. Anyone who can read the
        # container's stdout logs already has whatever access they'd get
        # from this key, so there is no additional exposure in logging it —
        # and no other channel exists to hand it to the person starting the
        # container for the first time.
        print(f"Frogscope access key (save this): {auth_key}", flush=True)

    @app.before_request
    def _require_auth_key():
        path = request.path
        if path in _UNGATED_PATHS or path.startswith(_UNGATED_PREFIXES):
            return None
        submitted = request.headers.get("X-Auth-Key", "")
        if not secrets.compare_digest(submitted, app.config["FROGSCOPE_AUTH_KEY"]):
            return jsonify({"error": "missing or invalid access key"}), 401
        return None

    app.register_blueprint(api)
    app.teardown_appcontext(close_db)

    @app.get("/")
    def index():
        return render_template("index.html", config_hash=cfg.config_hash)

    @app.get("/healthz")
    def healthz():
        return {"ok": True, "config_hash": cfg.config_hash}

    return app
