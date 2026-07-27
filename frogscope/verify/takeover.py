"""Opt-in live verification of takeover candidates.

**This is the only part of frogscope that sends a packet.** Everything else works
from the CSV. It is a separate command, off by default, and it is deliberately
minimal in what it does:

* resolve the hostname and its CNAME target,
* issue one HTTP request per candidate and read the response,
* compare against the provider fingerprints already in `config/takeover.yaml`.

It does not attempt to claim, register, or take over anything. It does not probe
paths, fuzz, or authenticate. Confirming a candidate is a read-only observation —
does the CNAME target still resolve, and does the provider return its
"unclaimed resource" page — and the remediation is always the same regardless:
remove the record or re-claim the resource yourself.

Scope is limited to hosts already present in an ingested scan, so it cannot be
pointed at arbitrary targets, and requests are rate-limited and serialised per
host.
"""

from __future__ import annotations

import json
import socket
import sqlite3
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

USER_AGENT = "frogscope/verify (attack-surface inventory verification)"
DEFAULT_TIMEOUT = 8.0
DEFAULT_DELAY = 0.5


@dataclass
class Observation:
    host: str
    resolved: bool = False
    addresses: list[str] = field(default_factory=list)
    cname_chain: list[str] = field(default_factory=list)
    cname_target: str = ""
    cname_resolves: bool | None = None
    http_status: int | None = None
    http_error: str = ""
    body_sample: str = ""
    server: str = ""
    checks: list[dict[str, Any]] = field(default_factory=list)
    verdict: str = "unconfirmed"
    reason: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "host": self.host, "resolved": self.resolved,
            "addresses": self.addresses, "cname_chain": self.cname_chain,
            "cname_target": self.cname_target,
            "cname_resolves": self.cname_resolves,
            "http_status": self.http_status, "http_error": self.http_error,
            "server": self.server, "checks": self.checks,
            "verdict": self.verdict, "reason": self.reason,
        }


def _resolve(name: str, timeout: float) -> tuple[bool, list[str]]:
    socket.setdefaulttimeout(timeout)
    try:
        infos = socket.getaddrinfo(name, None)
    except socket.gaierror:
        return False, []
    except OSError:
        return False, []
    return True, sorted({info[4][0] for info in infos})


def _cname_chain(name: str, timeout: float, depth: int = 6) -> list[str]:
    """Follow CNAMEs using only the standard library.

    `getaddrinfo` does not expose the chain, so this walks it via
    `gethostbyname_ex`, whose alias list is the chain. Good enough to answer "does
    the target still exist", which is the only question here.
    """
    chain: list[str] = []
    current = name
    for _ in range(depth):
        try:
            canonical, aliases, _addresses = socket.gethostbyname_ex(current)
        except (socket.gaierror, OSError):
            break
        for alias in aliases:
            if alias not in chain and alias != name:
                chain.append(alias)
        if canonical and canonical != current:
            if canonical not in chain:
                chain.append(canonical)
            current = canonical
        else:
            break
    return chain


def _fetch(host: str, timeout: float, scheme: str = "https") -> Observation:
    observation = Observation(host=host)
    request = urllib.request.Request(
        f"{scheme}://{host}/",
        headers={"User-Agent": USER_AGENT, "Accept": "*/*"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            observation.http_status = response.status
            observation.server = response.headers.get("Server", "") or ""
            # A small sample is enough to match a provider's fixed error page,
            # and reading the whole body of an unknown host is neither necessary
            # nor polite.
            observation.body_sample = response.read(4096).decode(
                "utf-8", "replace")
    except urllib.error.HTTPError as exc:
        observation.http_status = exc.code
        observation.server = exc.headers.get("Server", "") if exc.headers else ""
        try:
            observation.body_sample = exc.read(4096).decode("utf-8", "replace")
        except Exception:
            pass
    except (TimeoutError, urllib.error.URLError, OSError) as exc:
        observation.http_error = str(getattr(exc, "reason", exc))[:200]
    return observation


def verify_candidate(candidate: dict, takeover_cfg: dict, *,
                     timeout: float = DEFAULT_TIMEOUT,
                     do_http: bool = True) -> Observation:
    """Check one candidate. Read-only: resolve, fetch, compare."""
    host = candidate["host"]
    observation = Observation(host=host)

    observation.resolved, observation.addresses = _resolve(host, timeout)
    observation.checks.append({
        "test": "hostname resolves",
        "observed": (", ".join(observation.addresses[:4])
                     if observation.resolved else "NXDOMAIN or no address"),
        "verdict": "resolves" if observation.resolved else "does not resolve",
    })

    observation.cname_chain = _cname_chain(host, timeout)
    observation.cname_target = (
        observation.cname_chain[-1] if observation.cname_chain
        else (candidate.get("cname_final") or ""))

    if observation.cname_target and observation.cname_target != host:
        resolves, addresses = _resolve(observation.cname_target, timeout)
        observation.cname_resolves = resolves
        observation.checks.append({
            "test": "CNAME target resolves",
            "observed": f"{observation.cname_target} -> "
                        + (", ".join(addresses[:3]) if resolves
                           else "NXDOMAIN"),
            "verdict": "target exists" if resolves else "target is gone",
        })

    if do_http:
        fetched = _fetch(host, timeout)
        observation.http_status = fetched.http_status
        observation.http_error = fetched.http_error
        observation.server = fetched.server
        observation.body_sample = fetched.body_sample
        observation.checks.append({
            "test": "HTTP response",
            "observed": (f"status {fetched.http_status}"
                         if fetched.http_status is not None
                         else f"no response ({fetched.http_error})"),
            "verdict": "responded" if fetched.http_status is not None
                       else "no response",
        })

    _judge(candidate, observation, takeover_cfg, http_checked=do_http)
    return observation


def _judge(candidate: dict, observation: Observation, takeover_cfg: dict,
           http_checked: bool = True) -> None:
    """Decide what the observations mean.

    "Confirmed" requires the provider's own unclaimed-resource fingerprint in the
    live body. Anything weaker stays a candidate — a dangling record that has not
    yet been claimed still looks a lot like a healthy one from outside.
    """
    provider_name = (candidate.get("provider") or "").lower()
    matched = None
    for entry in takeover_cfg.get("providers") or []:
        if str(entry.get("provider", "")).lower() == provider_name:
            matched = entry
            break

    body = (observation.body_sample or "").lower()
    fingerprints = []
    if matched:
        fingerprints = [
            *(matched.get("body_fingerprints") or []),
            *(matched.get("title_fingerprints") or []),
        ]

    hit = next((f for f in fingerprints if str(f).lower() in body), None)

    if hit:
        observation.verdict = "confirmed"
        observation.reason = (
            f"The live response contains {matched['provider']}'s "
            f"unclaimed-resource fingerprint ({hit!r}). If that provider allows "
            f"the name to be registered, someone else can serve content on this "
            f"hostname."
        )
        observation.checks.append({
            "test": "provider fingerprint",
            "observed": f"body contains {hit!r}",
            "verdict": "confirmed dangling",
        })
        return

    if observation.cname_resolves is False:
        observation.verdict = "likely"
        observation.reason = (
            f"The CNAME target {observation.cname_target} no longer resolves, so "
            f"this hostname points at nothing. Whether it is claimable depends on "
            f"the provider."
        )
        return

    if not observation.resolved:
        observation.verdict = "stale_record"
        observation.reason = (
            "The hostname itself no longer resolves. Nothing is exposed right "
            "now, but the DNS record should still be removed."
        )
        return

    if (http_checked and observation.http_status is not None
            and observation.http_status < 400):
        observation.verdict = "not_dangling"
        observation.reason = (
            f"The hostname resolves and returns HTTP {observation.http_status}, "
            f"so something is serving it. This looks like a false positive from "
            f"the scan data."
        )
        return

    observation.verdict = "unconfirmed"
    if not http_checked:
        # Saying "unconfirmed" without this would imply the fingerprint check ran
        # and found nothing, when it never ran at all. Several classes — a
        # Cloudflare 530 among them — are only visible in an HTTP response.
        observation.reason = (
            "DNS resolves and so does the CNAME target, but no HTTP request was "
            "made (--dns-only), so the provider fingerprint was never checked. "
            "Several dangling patterns, including a Cloudflare 530, are only "
            "visible in the response body. Re-run without --dns-only to decide."
        )
    else:
        observation.reason = (
            "Nothing observed either confirms or rules this out. The target "
            "resolves but the response carries no provider fingerprint, so a "
            "manual look is needed."
        )


def verify_run(conn: sqlite3.Connection, run: sqlite3.Row, ruleset, *,
               timeout: float = DEFAULT_TIMEOUT,
               delay: float = DEFAULT_DELAY,
               do_http: bool = True,
               limit: int | None = None,
               on_progress=None) -> dict[str, Any]:
    """Verify every takeover candidate in a run.

    Scope is the candidates already found in that run, so this cannot be aimed at
    hosts the scan never saw.
    """
    from ..analytics import inventory as inv

    data = inv.takeover(conn, run["id"], ruleset.takeover)
    candidates = data["candidates"][:limit] if limit else data["candidates"]

    results: list[dict[str, Any]] = []
    for index, candidate in enumerate(candidates):
        if on_progress:
            on_progress(index + 1, len(candidates), candidate["host"])
        observation = verify_candidate(candidate, ruleset.takeover,
                                       timeout=timeout, do_http=do_http)
        results.append({
            "host": candidate["host"],
            "scan_grade": candidate["grade"],
            "scan_confidence": candidate["confidence"],
            "provider": candidate["provider"],
            **observation.as_dict(),
        })
        # Serialised with a delay: a handful of candidates does not warrant
        # concurrency, and this keeps the footprint on someone else's
        # infrastructure negligible.
        if delay and index + 1 < len(candidates):
            time.sleep(delay)

    verdicts: dict[str, int] = {}
    for result in results:
        verdicts[result["verdict"]] = verdicts.get(result["verdict"], 0) + 1

    return {
        "run_id": run["id"],
        "run_key": run["run_key"],
        "checked": len(results),
        "candidates_in_run": len(data["candidates"]),
        "by_verdict": verdicts,
        "results": results,
    }


def persist(conn: sqlite3.Connection, run_id: int,
            outcome: dict[str, Any]) -> None:
    """Store the verification alongside the run.

    Kept separate from the scan-derived grade rather than overwriting it: the
    scan said what it could see, and the verification is a later, independent
    observation. Merging them would lose the distinction.
    """
    conn.execute(
        "UPDATE runs SET verify_json = ? WHERE id = ?",
        (json.dumps(outcome, default=str), run_id),
    )
    conn.commit()
