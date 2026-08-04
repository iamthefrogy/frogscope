"""Fast, fail-fast checks before a scan starts spending time or sending
traffic.

A wide scan that discovers "DNS is broken" or "there's no outbound network"
reactively — one dropped domain at a time, over the course of minutes —
produces a confusing, silently-partial result that looks like ordinary scan
noise. These checks answer the same question up front, in a few seconds, so
a bad environment fails loudly and immediately instead of masquerading as a
flaky scan.

Binary presence (`tools.missing()`) is deliberately not repeated here — the
caller (`ScanRun.run()`) already checks that first, as the cheapest possible
gate, before this module's network probes ever run.
"""

from __future__ import annotations

import os
import socket
from concurrent.futures import ThreadPoolExecutor

from . import options as opts
from .runner import ScanError

# An env var, not a scan option: this exists for restricted-network
# deployments (e.g. an outbound proxy that a raw TCP connect can't see
# through) where even a single benign probe is blocked by policy, not for
# per-scan tuning.
SKIP_ENV_VAR = "FROGSCOPE_SKIP_PREFLIGHT"

# Two well-known names, not one — a single lookup failing could be that name
# having a bad day rather than a broken resolver.
_DNS_PROBE_HOSTS = ("google.com", "cloudflare.com")

# Reachability, not resolution: an IP:port needs no DNS, so this is checked
# separately from `_check_dns` — a failure here says "egress is blocked",
# not "DNS is broken", and the two need different fixes.
_REACHABILITY_HOST = "1.1.1.1"
_REACHABILITY_PORT = 443

_PROBE_TIMEOUT = 3.0


class PreflightError(ScanError):
    """A precondition this machine/network doesn't meet — raised before any
    subprocess or workdir is created, so the caller has spent nothing yet."""


def _check_dns() -> str | None:
    for host in _DNS_PROBE_HOSTS:
        try:
            socket.getaddrinfo(host, 443)
            return None
        except OSError:
            continue
    return (
        f"DNS resolution failed for every probe host ({', '.join(_DNS_PROBE_HOSTS)}) "
        f"— the resolver this machine sees is not working"
    )


def _check_reachability() -> str | None:
    try:
        socket.create_connection(
            (_REACHABILITY_HOST, _REACHABILITY_PORT), timeout=_PROBE_TIMEOUT).close()
        return None
    except OSError as exc:
        return (
            f"couldn't reach {_REACHABILITY_HOST}:{_REACHABILITY_PORT} ({exc}) "
            f"— outbound network access looks blocked"
        )


def run(options: opts.ScanOptions) -> None:
    """Raise `PreflightError` if this machine can't do what a scan needs.

    DNS is only checked for a domain-based scan — a pure IP/CIDR scan never
    resolves a name, so a broken resolver is irrelevant to it.
    """
    if os.environ.get(SKIP_ENV_VAR):
        return

    checks = [_check_reachability]
    if options.domains:
        checks.append(_check_dns)

    with ThreadPoolExecutor(max_workers=len(checks)) as pool:
        problems = [p for p in pool.map(lambda fn: fn(), checks) if p]

    if problems:
        raise PreflightError(
            "preflight check failed: " + "; ".join(problems) +
            f". If this is expected for this environment, set "
            f"{SKIP_ENV_VAR}=1 to bypass it."
        )
