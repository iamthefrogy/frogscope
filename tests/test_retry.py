"""frogscope.scan.retry: bounded retry with backoff for a scanner
subprocess call."""

from __future__ import annotations

import pytest

from frogscope.scan import retry


def test_succeeds_first_try_without_sleeping(monkeypatch):
    monkeypatch.setattr(retry.time, "sleep",
                        lambda *a: (_ for _ in ()).throw(
                            AssertionError("should not sleep")))
    calls = []

    def fn():
        calls.append(1)
        return "ok"

    result = retry.call_with_backoff(
        fn, attempts=3, base_delay_s=1, max_delay_s=10)
    assert result == "ok"
    assert len(calls) == 1


def test_succeeds_after_failures(monkeypatch):
    sleeps = []
    monkeypatch.setattr(retry.time, "sleep", lambda s: sleeps.append(s))

    calls = {"n": 0}

    def fn():
        calls["n"] += 1
        if calls["n"] < 3:
            raise RuntimeError(f"fail {calls['n']}")
        return "ok"

    result = retry.call_with_backoff(
        fn, attempts=5, base_delay_s=1, max_delay_s=10)
    assert result == "ok"
    assert calls["n"] == 3
    assert len(sleeps) == 2  # slept between attempt 1->2 and 2->3


def test_exhausts_attempts_and_reraises_last_exception(monkeypatch):
    monkeypatch.setattr(retry.time, "sleep", lambda s: None)

    def fn():
        raise RuntimeError("always fails")

    with pytest.raises(RuntimeError, match="always fails"):
        retry.call_with_backoff(fn, attempts=3, base_delay_s=1, max_delay_s=10)


def test_stops_immediately_on_cancellation_without_sleeping(monkeypatch):
    monkeypatch.setattr(retry.time, "sleep",
                        lambda *a: (_ for _ in ()).throw(
                            AssertionError("should not sleep once cancelled")))

    def fn():
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError, match="boom"):
        retry.call_with_backoff(
            fn, attempts=5, base_delay_s=1, max_delay_s=10,
            is_cancelled=lambda: True)


def test_backoff_delay_doubles_and_is_capped(monkeypatch):
    sleeps = []
    monkeypatch.setattr(retry.time, "sleep", lambda s: sleeps.append(s))
    # No jitter, to make the doubling/cap assertions exact.
    monkeypatch.setattr(retry.random, "uniform", lambda a, b: 0)

    def fn():
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        retry.call_with_backoff(
            fn, attempts=5, base_delay_s=2, max_delay_s=5)

    assert sleeps == [2, 4, 5, 5]  # 2, 4, capped at 5, capped at 5


def test_on_retry_callback_fires_once_per_retry(monkeypatch):
    monkeypatch.setattr(retry.time, "sleep", lambda s: None)
    seen = []

    def fn():
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        retry.call_with_backoff(
            fn, attempts=3, base_delay_s=1, max_delay_s=10,
            on_retry=lambda attempt, exc: seen.append((attempt, str(exc))))

    assert seen == [(1, "boom"), (2, "boom")]  # not called after the last attempt


def test_attempts_must_be_at_least_one():
    with pytest.raises(ValueError):
        retry.call_with_backoff(lambda: "x", attempts=0, base_delay_s=1, max_delay_s=1)
