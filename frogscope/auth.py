"""App-wide access key.

Frogscope has no user accounts, deliberately — it is a single-tenant tool run
by the team that owns the estate it scans, not a multi-user service. But
`docker-compose.yml` binds to `127.0.0.1` specifically "because this app has
no authentication by design" (its own comment, verbatim) — the moment it
becomes reachable from anywhere else (a shared server, a reverse proxy, a
docker network with other containers on it), that assumption quietly breaks
and nothing stops another process on the same host, or the same network,
from opening the dashboard.

This is a single shared key, not a login system: generated once on first
container start (not at `docker build` — `/data` is a runtime-mounted
volume, so a build-time key would bake one identical value into every image
pulled from that build, and never rotate), checked on every `/api/*` request
via an `X-Auth-Key` header. Rotating it logs everyone out at once, which is
correct for a shared-key model with no per-user identity to preserve
selectively.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path

KEY_FILE_NAME = "auth.key"
ENV_VAR = "FROGSCOPE_AUTH_KEY"


def get_or_create_key(data_dir: Path) -> tuple[str, bool]:
    """The key checked against every request, and whether it was just
    generated (so the caller can decide whether to log it — once, on first
    creation, never on every subsequent restart that simply reuses the file).

    `FROGSCOPE_AUTH_KEY` overrides the stored file entirely — useful for
    docker-compose or CI, where a fixed key set via environment is more
    convenient than reading container logs for a generated one.
    """
    env_key = os.environ.get(ENV_VAR)
    if env_key:
        return env_key, False

    path = data_dir / KEY_FILE_NAME
    if path.exists():
        return path.read_text(encoding="utf-8").strip(), False

    return _write_new_key(path), True


def rotate_key(data_dir: Path) -> str:
    """Generate and store a fresh key, invalidating the old one immediately —
    effectively logging out every current session, since there is no
    per-user identity here to preserve selectively."""
    return _write_new_key(data_dir / KEY_FILE_NAME)


def _write_new_key(path: Path) -> str:
    key = secrets.token_urlsafe(32)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(key, encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass  # best-effort — some mounted filesystems (e.g. certain volume
              # drivers) don't support POSIX permission bits at all.
    return key
