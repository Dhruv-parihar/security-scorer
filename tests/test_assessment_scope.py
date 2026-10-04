"""Tests preventing cross-target composite attribution."""
from modules.assessment_scope import validate_composite_scope


def test_same_remote_target_may_be_composited():
    error, target_id = validate_composite_scope(
        {"network": {"score": 50}, "webapp": {"score": 70}},
        {"network": "target-a", "webapp": "target-a"},
    )
    assert error is None
    assert target_id == "target-a"


def test_different_remote_targets_are_blocked():
    error, target_id = validate_composite_scope(
        {"network": {"score": 50}, "webapp": {"score": 70}},
        {"network": "target-a", "webapp": "target-b"},
    )
    assert "different target records" in error
    assert target_id is None


def test_local_os_and_remote_result_are_blocked():
    error, target_id = validate_composite_scope(
        {"os_hardening": {"score": 50}, "network": {"score": 70}},
        {"network": "target-a"},
    )
    assert "local OS hardening" in error
    assert target_id is None
