"""Guards that prevent combining observations from different targets."""


def local_os_target_family_error(observed_family, registered_family):
    """Return an error when a known local OS family conflicts with its target."""
    observed = str(observed_family or "").strip().lower()
    registered = str(registered_family or "").strip().lower()
    if observed in ("", "unknown") or registered in ("", "unknown"):
        return None
    if observed != registered:
        return (
            f"Local OS family '{observed}' does not match the registered "
            f"target OS family '{registered}'. The result was not bound."
        )
    return None


def validate_composite_scope(layer_results, target_ids):
    """Return (error_message_or_none, persisted_target_id_or_none).

    OS hardening runs locally. It may be persisted alone when an explicit
    authorized local-target binding is supplied. It may be combined with
    network/web results only when that explicit binding resolves to the same
    target record. Network and web results may be combined only when they
    resolve to exactly one target record.
    """
    local_id = (
        target_ids.get("os_hardening")
        if "os_hardening" in layer_results else None
    )
    active_ids = {
        target_id for layer, target_id in target_ids.items()
        if layer in ("network", "webapp") and target_id is not None
    }
    if len(active_ids) > 1:
        return (
            "Composite and persistence blocked: active scan results map to "
            "different target records.",
            None,
        )
    if "os_hardening" in layer_results and active_ids and local_id is None:
        return (
            "Composite blocked: local OS hardening needs an explicit local "
            "target binding before it can be combined with remote scan results.",
            None,
        )
    if local_id is not None and active_ids and local_id not in active_ids:
        return (
            "Composite and persistence blocked: local OS and active scan "
            "results map to different target records.",
            None,
        )
    if local_id is not None:
        return None, local_id
    return None, next(iter(active_ids), None)
