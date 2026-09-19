"""
Scanner → Research Database Adapter (Phase 2)
=============================================
Translates existing scanner dict output into Phase 1 research DB records.

Design:
- Does NOT duplicate scanner detection logic.
- Does NOT modify scanner module behavior.
- Preserves existing JSON output format (backward compatible).
- Raw observations are stored as findings (primary research data).
- Scores are stored as score_snapshots (derived artifacts).
- NOT_APPLICABLE findings are preserved with severity=None as required.
- No secrets or PII are stored.

Usage:
    from db.adapters import store_assessment_results
    snapshot_id = store_assessment_results(
        conn, target_id, layer_results, composite_result
    )
"""

import json
from datetime import datetime, timezone
from db.repository import (
    create_assessment, close_assessment,
    create_finding, create_score_snapshot, create_remediation,
    get_taxonomy_id,
)

# Map scanner layer keys → DB layer values
LAYER_MAP = {
    "os_hardening": "OS",
    "network": "NETWORK",
    "webapp": "WEB",
}

# Map scanner severity strings → normalized values
SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "informational",
    None: None,
}

# Map scanner finding status → DB status
# OS/webapp findings use "passed" (bool) or "status" (str if R2/R3 applied)
# Network findings have no "passed" key — severity presence = FAIL
def _infer_status(finding, layer_key):
    """
    Infer DB finding status from scanner dict.

    OS/webapp (after R2/R3 fix): use "status" field directly if present.
    OS/webapp (pre-fix or PASS/FAIL only): use "passed" bool.
    Network: no "passed" key — any finding in the list with severity is FAIL.
    """
    # Prefer explicit status field (R2/R3 fix adds this)
    explicit_status = finding.get("status")
    if explicit_status in ("PASS", "FAIL", "NOT_APPLICABLE", "NOT_TESTED", "ERROR", "UNKNOWN"):
        return explicit_status

    # Fallback: passed bool (pre-fix os/webapp format)
    passed_val = finding.get("passed", None)
    if passed_val is True:
        return "PASS"
    if passed_val is False:
        return "FAIL"

    # Network style: no passed key, severity present = FAIL
    if passed_val is None and layer_key == "network":
        severity = finding.get("severity")
        if severity is not None:
            return "FAIL"

    return "UNKNOWN"


def _infer_severity(finding, status):
    """
    Normalize severity. NOT_APPLICABLE must have None severity.
    """
    if status in ("NOT_APPLICABLE", "NOT_TESTED"):
        return None
    raw = finding.get("severity")
    return SEVERITY_MAP.get(raw, raw)


def _extract_evidence(finding, layer_key):
    """Build an evidence string from available finding fields."""
    parts = {}
    if layer_key == "network":
        for k in ("port", "service", "version", "matched_signature"):
            if finding.get(k):
                parts[k] = finding[k]
    if finding.get("not_applicable_reason"):
        parts["not_applicable_reason"] = finding["not_applicable_reason"]
    return json.dumps(parts) if parts else None


def store_assessment_results(
    conn, target_id, layer_results, composite_result,
    tool_version="1.0.0", methodology_version="1.0",
    assessor=None, notes=None,
    scoring_model_id="weighted_composite_v1",
    scoring_model_ver="1.0",
    weight_os=0.30, weight_network=0.35, weight_web=0.35,
):
    """
    Persist a complete scan run into the research database.

    Parameters:
        conn:             open DB connection
        target_id:        target UUID (must exist, must be authorized)
        layer_results:    dict of scanner results (same as passed to scoring.py)
        composite_result: output of scoring.compute_composite()
        tool_version:     scanner tool version string
        methodology_version: research methodology version string
        assessor:         anonymized assessor identifier (optional)
        notes:            free-text notes (optional)

    Returns:
        assessment_id: UUID string of the created assessment record
    """
    # Determine scope from which layers were actually run
    present = [k for k, v in layer_results.items() if v is not None]
    scope = "ALL" if len(present) >= 3 else "/".join(
        LAYER_MAP.get(k, k.upper()) for k in present
    )

    # We need authorization_status — read from target record
    target_row = conn.execute(
        "SELECT authorization_status FROM target WHERE target_id = ?",
        (target_id,)
    ).fetchone()
    if target_row is None:
        raise ValueError(f"Target {target_id} not found in database")
    authorization_status = target_row["authorization_status"]

    # Create assessment
    assessment_id = create_assessment(
        conn, target_id=target_id, scope=scope,
        authorization_status=authorization_status,
        tool_version=tool_version,
        methodology_version=methodology_version,
        assessor=assessor, notes=notes,
    )

    # Store findings for each layer
    for layer_key, result in layer_results.items():
        if result is None:
            continue
        db_layer = LAYER_MAP.get(layer_key)
        if db_layer is None:
            continue

        for finding in result.get("findings", []):
            status = _infer_status(finding, layer_key)
            severity = _infer_severity(finding, status)
            evidence = _extract_evidence(finding, layer_key)

            # Get check_id: use "id" (os/webapp) or compose from port+service (network)
            check_id = finding.get("id") or (
                f"port_{finding.get('port', 'unknown')}_{finding.get('service', 'unknown')}"
                if layer_key == "network" else "unknown_check"
            )

            description = (
                finding.get("description")
                or finding.get("note")
                or check_id
            )

            recommendation = finding.get("recommendation")
            standard_ref = finding.get("standard_ref")  # present in some network findings

            # Map to taxonomy where possible
            taxonomy_id = _get_taxonomy_for_check(conn, check_id, layer_key)

            finding_id = create_finding(
                conn,
                assessment_id=assessment_id,
                layer=db_layer,
                check_id=check_id,
                status=status,
                description=description,
                severity=severity,
                evidence=evidence,
                recommendation=recommendation,
                standard_ref=standard_ref,
                taxonomy_id=taxonomy_id,
            )

            # Create pending remediation for FAIL findings
            if status == "FAIL" and recommendation:
                create_remediation(conn, finding_id, recommendation)

    # Store score snapshot (derived artifact)
    if composite_result and composite_result.get("composite_score") is not None:
        create_score_snapshot(
            conn,
            assessment_id=assessment_id,
            composite_result=composite_result,
            scoring_model_id=scoring_model_id,
            scoring_model_ver=scoring_model_ver,
            weight_os=weight_os,
            weight_network=weight_network,
            weight_web=weight_web,
        )

    close_assessment(conn, assessment_id)
    return assessment_id


# ── Taxonomy mapping ──────────────────────────────────────────────────────────

_CHECK_TAXONOMY = {
    # OS checks
    "ssh_root_login": ("AUTHENTICATION", None),
    "password_max_days": ("AUTHENTICATION", None),
    "firewall_active": ("EXPOSURE", None),
    "world_writable_files": ("ACCESS_CONTROL", None),
    "automatic_updates": ("PATCHING", None),
    "guest_account_disabled": ("AUTHENTICATION", None),
    # Web checks
    "header_content_security_policy": ("CONFIGURATION", None),
    "header_x_frame_options": ("CONFIGURATION", None),
    "header_strict_transport_security": ("CONFIGURATION", None),
    "header_x_content_type_options": ("CONFIGURATION", None),
    "reflected_sqli_heuristic": ("INPUT_VALIDATION", None),
    "reflected_xss_heuristic": ("INPUT_VALIDATION", None),
}

_NETWORK_TAXONOMY = {
    "critical": ("OUTDATED_SOFTWARE", None),
    "high": ("OUTDATED_SOFTWARE", None),
    "medium": ("UNNECESSARY_SERVICE", None),
    "low": ("UNNECESSARY_SERVICE", None),
}


def _get_taxonomy_for_check(conn, check_id, layer_key):
    """Return taxonomy_id for a check_id, or None if not mapped."""
    mapping = _CHECK_TAXONOMY.get(check_id)
    if mapping is None and layer_key == "network":
        return None  # network findings get no taxonomy (too generic per-port)
    if mapping:
        return get_taxonomy_id(conn, mapping[0], mapping[1])
    return None
