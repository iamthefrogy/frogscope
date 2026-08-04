"""frogscope.ingest.quality.truncation_check: telling a truncated scan
(same host list, far fewer rows because httpx died partway through) apart
from a legitimately different one (a bigger/smaller portfolio, or a
port-profile change) — see scan/executor.py for why a blanket
`allow_drift=True` used to swallow exactly this case."""

from __future__ import annotations

from frogscope.ingest import quality


def test_falls_back_to_plain_drift_check_when_hosts_submitted_is_unknown():
    """An upload, or a run ingested before this signal existed, has no
    host-list signal — must behave exactly like the old `drift_check`, and
    never be flagged as a suspected truncation."""
    warning, suspected = quality.truncation_check(
        10, 100,
        hosts_submitted=None, previous_hosts_submitted=300,
        ports_prescoped=None, previous_ports_prescoped=None,
    )
    assert warning is not None
    assert "changed by" in warning
    assert suspected is False


def test_same_host_list_and_a_big_swing_is_a_suspected_truncation():
    """The reported bug's exact signature: ~300 domains submitted both
    times, endpoint count collapsed."""
    warning, suspected = quality.truncation_check(
        3, 168,
        hosts_submitted=2910, previous_hosts_submitted=2905,
        ports_prescoped=True, previous_ports_prescoped=True,
    )
    assert suspected is True
    assert "168 -> 3" in warning
    assert "truncated" in warning


def test_a_smaller_target_list_is_not_flagged_as_truncation():
    """Submitting fewer hosts than last time is a real, legitimate reason
    for fewer endpoints — not a truncation."""
    warning, suspected = quality.truncation_check(
        10, 100,
        hosts_submitted=50, previous_hosts_submitted=500,
        ports_prescoped=True, previous_ports_prescoped=True,
    )
    assert suspected is False
    assert warning is not None
    assert "target list also changed" in warning


def test_naabu_fallback_flip_is_explained_not_flagged_as_truncation():
    """naabu degrading from a scoped run to a full-profile fallback (or vice
    versa) is a known, explained cause of a different count — informative,
    not blocking."""
    warning, suspected = quality.truncation_check(
        500, 100,
        hosts_submitted=300, previous_hosts_submitted=300,
        ports_prescoped=False, previous_ports_prescoped=True,
    )
    assert suspected is False
    assert warning is not None
    assert "naabu" in warning


def test_small_swings_produce_no_warning_at_all():
    warning, suspected = quality.truncation_check(
        105, 100,
        hosts_submitted=300, previous_hosts_submitted=300,
        ports_prescoped=True, previous_ports_prescoped=True,
    )
    assert warning is None
    assert suspected is False


def test_no_previous_run_produces_no_warning():
    warning, suspected = quality.truncation_check(
        50, None,
        hosts_submitted=300, previous_hosts_submitted=None,
        ports_prescoped=True, previous_ports_prescoped=None,
    )
    assert warning is None
    assert suspected is False
