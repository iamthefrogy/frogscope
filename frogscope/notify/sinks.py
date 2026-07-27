"""Delivery. The only place in this package that opens a socket.

Reached only when `notify.yaml:enabled` is true AND the caller passed `--send`.
Two locks rather than one because the failure mode is posting an organisation's
asset inventory to a channel nobody intended.

Three kinds:

* `slack`  — Block Kit, so severity reads at a glance in the channel.
* `webhook` — the whole alert as JSON, for anything else.
* `file`   — appends JSON Lines locally, sends nothing. This is how you check
  routing and see the exact payload without a webhook, and it is what the tests
  use.
"""

from __future__ import annotations

import json
import sqlite3
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from ..ingest.store import now_iso
from .alerts import Alert, AlertItem

USER_AGENT = "frogscope/notify"

_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "⚪",
          "info": "🔵"}
_LABEL = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM",
          "low": "LOW", "info": "INFO"}


# ── Formatting ──────────────────────────────────────────────────────────────

def slack_payload(alert: Alert, *, max_blocks: int = 40) -> dict[str, Any]:
    """Block Kit. Severity carries a glyph and a word, never colour alone."""
    blocks: list[dict[str, Any]] = [
        {"type": "header",
         "text": {"type": "plain_text", "text": f"frogscope — {alert.project}"}},
        {"type": "section", "text": {"type": "mrkdwn",
         "text": (f"*{alert.summary_line()}*\n"
                  f"Run `{alert.run_key}` · {alert.context.get('endpoints', 0)} "
                  f"endpoints across {alert.context.get('hosts', 0)} hosts")}},
    ]
    if not alert.items:
        blocks.append({"type": "section", "text": {"type": "mrkdwn",
                       "text": "_Nothing new. No action needed._"}})

    for item in alert.items:
        if len(blocks) >= max_blocks - 2:
            break
        glyph = _EMOJI.get(item.severity, "⚪")
        label = _LABEL.get(item.severity, item.severity.upper())
        line = f"{glyph} *{label}* — {item.headline}"
        if item.detail:
            line += f"\n{item.detail[:300]}"
        blocks.append({"type": "section",
                       "text": {"type": "mrkdwn", "text": line}})

    shown = sum(1 for b in blocks if b["type"] == "section") - 1
    if len(alert.items) > max(shown, 0):
        blocks.append({"type": "context", "elements": [{"type": "mrkdwn",
                       "text": f"_{len(alert.items) - shown} more items not "
                               f"shown — Slack caps blocks per message._"}]})
    for note in alert.suppressed:
        blocks.append({"type": "context",
                       "elements": [{"type": "mrkdwn", "text": f"_{note}_"}]})

    return {
        # `text` is the notification preview and the accessibility fallback, so
        # a client that renders no blocks still shows something useful.
        "text": alert.summary_line(),
        "blocks": blocks,
    }


def webhook_payload(alert: Alert) -> dict[str, Any]:
    return alert.as_dict()


def text_summary(alert: Alert) -> str:
    """Plain text, for a terminal preview."""
    lines = [alert.summary_line(),
             f"  run {alert.run_key}  ({alert.context.get('endpoints', 0)} "
             f"endpoints, {alert.context.get('hosts', 0)} hosts)"]
    for item in alert.items:
        lines.append(f"  {_LABEL.get(item.severity, item.severity):<8} "
                     f"{item.headline}")
        if item.detail:
            lines.append(f"           {item.detail[:160]}")
    for note in alert.suppressed:
        lines.append(f"  note: {note}")
    return "\n".join(lines)


# ── Delivery ────────────────────────────────────────────────────────────────

def _post(url: str, body: dict, timeout: float, retries: int,
          retry_delay: float) -> tuple[bool, str]:
    data = json.dumps(body, default=str).encode("utf-8")
    request = urllib.request.Request(
        url, data=data, method="POST",
        headers={"Content-Type": "application/json", "User-Agent": USER_AGENT})
    last = ""
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                if 200 <= response.status < 300:
                    return True, f"HTTP {response.status}"
                last = f"HTTP {response.status}"
        except urllib.error.HTTPError as exc:
            last = f"HTTP {exc.code}"
            # 4xx will not fix itself on a retry; only server-side and transport
            # failures are worth trying again.
            if exc.code < 500:
                return False, last
        except (urllib.error.URLError, OSError) as exc:
            last = str(getattr(exc, "reason", exc))[:200]
        if attempt < retries:
            time.sleep(retry_delay)
    return False, last


def _resolve_path(raw: str, data_dir: Path | None) -> Path:
    """Resolve a file target's path against the data directory.

    `notify.yaml` ships `data/notifications.jsonl`, which reads naturally from the
    project root. Joining that onto the data directory verbatim would give
    `data/data/notifications.jsonl`, so a leading `data/` is dropped.
    """
    path = Path(raw)
    if path.is_absolute() or data_dir is None:
        return path
    parts = path.parts
    if parts and parts[0] == Path(data_dir).name:
        path = Path(*parts[1:]) if len(parts) > 1 else Path("notifications.jsonl")
    return Path(data_dir) / path


def deliver(alert: Alert, target: dict, notify_cfg: dict, *,
            data_dir: Path | None = None,
            known_hosts: list[str] | None = None,
            dry_run: bool = False) -> tuple[bool, str]:
    """Send one alert to one target. Returns (delivered, message)."""
    kind = target.get("kind")
    delivery = notify_cfg.get("delivery") or {}
    timeout = float(delivery.get("timeout", 10))
    retries = int(delivery.get("retries", 2))
    retry_delay = float(delivery.get("retry_delay", 2))

    if target.get("redact"):
        if not known_hosts:
            # Refuse rather than send. `Redactor.text` only rewrites hostnames it
            # has been shown, so with no host list it is a no-op that returns the
            # text unchanged — a silent leak to the one channel that explicitly
            # asked not to receive real names.
            return False, ("redact is set but no host list was supplied, so "
                           "nothing would actually be redacted — refusing to send")
        alert = _redacted(alert, known_hosts)

    if kind == "slack":
        body = slack_payload(alert)
    elif kind == "webhook":
        body = webhook_payload(alert)
    elif kind == "file":
        body = webhook_payload(alert)
        path = _resolve_path(target["path"], data_dir)
        if dry_run:
            return False, f"dry run — would append to {path}"
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(body, default=str) + "\n")
        return True, f"appended to {path}"
    else:
        return False, f"unknown target kind {kind!r}"

    if dry_run:
        return False, f"dry run — would POST {len(json.dumps(body))} bytes"
    return _post(target["url"], body, timeout, retries, retry_delay)


def _redacted(alert: Alert, known_hosts: list[str]) -> Alert:
    """Pseudonymise hostnames for a channel outside the security team.

    Same salted, structure-preserving scheme as the workbook and the offline
    export, so `adm.iem.acme.com` stays recognisably three labels deep under one
    zone without naming anything.

    Every host in the run is registered first. `Redactor.text` substitutes only
    names it has already been given, and an alert's free text mentions hosts that
    are not its own subject — a redirect target, a shared origin — so registering
    just `item.asset` would leave those in the clear.
    """
    from ..export.redact import Redactor

    redactor = Redactor()
    for name in known_hosts:
        redactor.host(name)
    clone = Alert(project=alert.project, run_key=alert.run_key,
                  run_id=alert.run_id, project_id=alert.project_id,
                  scanned_at=alert.scanned_at, is_baseline=alert.is_baseline,
                  context=dict(alert.context), suppressed=list(alert.suppressed))
    clone.items = [
        AlertItem(trigger=i.trigger,
                  # The dedup key embeds the hostname — `finding:RULE:host` — so
                  # copying it verbatim leaks every name the headline just hid.
                  # Safe to rewrite: the ledger is written from the original
                  # alert, so dedup still keys on the real name.
                  dedup_key=redactor.text(i.dedup_key),
                  severity=i.severity,
                  headline=redactor.text(i.headline),
                  detail=redactor.text(i.detail),
                  asset=redactor.text(i.asset), url="")
        for i in alert.items
    ]
    clone.suppressed.append("hostnames pseudonymised for this channel")
    return clone


def record(conn: sqlite3.Connection, alert: Alert, target_name: str,
           items: list[AlertItem], status: str, error: str = "") -> None:
    """Write the ledger so nothing is ever sent twice.

    `INSERT OR IGNORE` against the (project, target, dedup_key) unique index: the
    ledger is the guard, so a concurrent or repeated run cannot double-post even
    if it re-derives the same items.
    """
    stamp = now_iso()
    conn.executemany(
        """INSERT OR IGNORE INTO notifications
             (project_id, run_id, target, dedup_key, trigger, severity,
              summary, status, error, sent_at)
           VALUES (?,?,?,?,?,?,?,?,?,?)""",
        [(alert.project_id, alert.run_id, target_name, item.dedup_key,
          item.trigger, item.severity, item.headline[:300], status,
          error[:300] or None, stamp) for item in items],
    )
    conn.commit()
