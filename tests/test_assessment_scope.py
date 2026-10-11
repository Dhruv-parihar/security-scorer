"""Tests preventing cross-target composite attribution."""
from modules.assessment_scope import (
    local_os_target_family_error,
    validate_composite_scope,
)


def test_local_os_binding_rejects_known_family_mismatch():
    error = local_os_target_family_error("Windows", "linux")
    assert "does not match" in error
    assert local_os_target_family_error("Windows", "WINDOWS") is None
    assert local_os_target_family_error("unknown", "macos") is None


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


def test_local_os_only_persists_with_explicit_target_binding():
    error, target_id = validate_composite_scope(
        {"os_hardening": {"score": 50}},
        {"os_hardening": "local-target"},
    )
    assert error is None
    assert target_id == "local-target"


def test_local_os_and_remote_result_allowed_only_for_same_binding():
    layer_results = {
        "os_hardening": {"score": 50},
        "network": {"score": 70},
    }
    error, target_id = validate_composite_scope(
        layer_results,
        {"os_hardening": "same-target", "network": "same-target"},
    )
    assert error is None
    assert target_id == "same-target"

    error, target_id = validate_composite_scope(
        layer_results,
        {"os_hardening": "local-machine", "network": "remote-host"},
    )
    assert "different target records" in error
    assert target_id is None


def test_local_os_target_binding_without_os_layer_is_ignored():
    error, target_id = validate_composite_scope(
        {"network": {"score": 70}},
        {"os_hardening": "unrelated-target", "network": "network-target"},
    )
    assert error is None
    assert target_id == "network-target"
