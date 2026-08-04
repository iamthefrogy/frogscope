"""Bounded retry with exponential backoff for a scanner subprocess.

A subfinder/naabu/dnsx call failing once is very often a transient blip — a
rate-limited passive source, a dropped connection under a NAT'd network path
— not a real, permanent failure. Retrying a few times with backoff turns
that blip into a slower success instead of a silently-dropped result.
"""

from __future__ import annotations

import random
import time
from collections.abc import Callable
from typing import TypeVar

T = TypeVar("T")


def call_with_backoff(
    fn: Callable[[], T],
    *,
    attempts: int,
    base_delay_s: float,
    max_delay_s: float,
    is_cancelled: Callable[[], bool] = lambda: False,
    on_retry: Callable[[int, Exception], None] | None = None,
) -> T:
    """Call `fn()` up to `attempts` times, doubling the delay between
    attempts (capped at `max_delay_s`, with a little jitter so several
    concurrent callers retrying the same failing upstream don't all wake up
    at the exact same moment). Stops immediately, without sleeping or
    retrying again, once `is_cancelled()` is true. Re-raises the last
    exception once attempts are exhausted.
    """
    if attempts < 1:
        raise ValueError("attempts must be at least 1")

    for attempt in range(1, attempts + 1):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 — deliberately generic, see module docstring
            if attempt == attempts or is_cancelled():
                raise
            if on_retry is not None:
                on_retry(attempt, exc)
            delay = min(base_delay_s * (2 ** (attempt - 1)), max_delay_s)
            delay += random.uniform(0, delay * 0.1)
            time.sleep(delay)

    # Unreachable: the loop above always either returns or raises.
    raise AssertionError("unreachable")
