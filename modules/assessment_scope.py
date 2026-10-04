"""Guards that prevent combining observations from different targets."""


def validate_composite_scope(layer_results, target_ids):
    """Return (error_message_or_none, persisted_target_id_or_none).

    OS hardening runs locally and therefore has no remote target binding in the
    current interface. It cannot be combined with active remote scan results
    without an explicit, future local-target binding. Network and web results
    may be combined only when they resolve to exactly one target record.
    """
    active_ids = {
        target_id for layer, target_id in target_ids.items()
        if layer in ("network", "webapp") and target_id is not None
    }
    if "os_hardening" in layer_results and active_ids:
        return (
            "Composite blocked: local OS hardening cannot be attributed to a "
            "remote network or web target without an explicit target binding.",
            None,
        )
    if len(active_ids) > 1:
        return (
            "Composite and persistence blocked: active scan results map to "
            "different target records.",
            None,
        )
    return None, next(iter(active_ids), None)
