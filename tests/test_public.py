import pytest

from reputation import (
    add_event,
    decay,
    is_blocked,
    normalize_addr,
    reputation_batch,
    score,
)


def test_normalize_addr_unifies_written_forms():
    assert normalize_addr(" 192.168.000.010 ") == "192.168.0.10"
    assert normalize_addr("2001:0DB8:0:0:0:0:0:1") == "2001:db8::1"


def test_events_accumulate_and_duplicate_reports_count_once():
    state = {}
    add_event(state, "10.0.0.1", "login_failed", 0.0, 30.0)
    add_event(state, "10.0.0.1", "login_failed", 1.0, 30.0)
    add_event(state, "10.0.0.1", "port_scan", 2.0, 20.0)

    assert score(state, "10.0.0.1", 2.0) == pytest.approx(50.0)


def test_decay_halves_score_after_one_half_life():
    state = {}
    add_event(state, "10.0.0.9", "credential_stuffing", 0.0, 80.0)

    remaining = decay(state, "10.0.0.9", 10.0, 10.0)

    assert remaining == pytest.approx(40.0)
    assert score(state, "10.0.0.9", 10.0) == pytest.approx(40.0)


def test_block_at_threshold_is_blocked():
    state = {}
    add_event(state, "198.51.100.7", "credential_stuffing", 0.0, 100.0)
    policy = {
        "block_threshold": 100.0,
        "half_life": 10.0,
        "allowlist": ["203.0.113.0/24"],
    }

    assert is_blocked(state, "198.51.100.7", 0.0, policy) is True


def test_batch_scores_two_addresses_independently():
    events = [
        {"addr": "10.1.0.1", "event": "login_failed", "now": 0.0, "weight": 40.0},
        {"addr": "10.1.0.2", "event": "port_scan", "now": 0.0, "weight": 7.0},
    ]
    policy = {
        "block_threshold": 100.0,
        "half_life": 10.0,
        "allowlist": ["203.0.113.0/24"],
    }

    result = reputation_batch(events, policy)

    assert result["10.1.0.1"] == pytest.approx(40.0)
    assert result["10.1.0.2"] == pytest.approx(7.0)