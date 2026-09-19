"""
Research Database Repository
=============================
All database read/write operations go through this module.
Scanner modules never import this directly — the CLI/Flask layer
calls these functions after receiving scanner results.

Design: thin repository pattern. No business logic here.
"""

import uuid
from datetime import datetime, timezone
from db.schema import get_connection, FINDING_STATUSES, FINDING_LAYERS, AUTH_STATUSES


def _now():
    return datetime.now(timezone.utc).isoformat()


def _uuid():
    return str(uuid.uuid4())


# ── TARGET ───────────────────────────────────────────────────────────────────

def create_target(conn, alias, target_type, environment, authorization_status,
                  os_family=None, os_name=None, os_version=None,
                  deployment_type=None, technology_notes=None,
                  authorization_ref=None, notes=None):
    """
    Create a new anonymized research target.
    Returns target_id (UUID string).
    """
    assert authorization_status in AUTH_STATUSES, \
        f"Invalid authorization_status: {authorization_status}"
    target_id = _uuid()
    conn.execute("""
        INSERT INTO target (
            target_id, target_alias, target_type, environment,
            os_family, os_name, os_version, deployment_type,
            technology_notes, authorization_status, authorization_ref,
            created_at, notes
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (target_id, alias, target_type, environment,
          os_family, os_name, os_version, deployment_type,
          technology_notes, authorization_status, authorization_ref,
          _now(), notes))
    conn.commit()
    return target_id


def get_target(conn, target_id):
    return conn.execute(
        "SELECT * FROM target WHERE target_id = ?", (target_id,)
    ).fetchone()


def list_targets(conn):
    return conn.execute("SELECT * FROM target ORDER BY created_at").fetchall()


# ── ASSESSMENT ───────────────────────────────────────────────────────────────

def create_assessment(conn, target_id, scope, authorization_status,
                      tool_version="1.0.0", methodology_version="1.0",
                      schema_version=1, assessor=None, notes=None,
                      start_time=None, end_time=None):
    """
    Create a new assessment record for a target.
    Returns assessment_id (UUID string).
    target_id must already exist.
    authorization_status must match or be a subset of target's auth.
    """
    assert authorization_status in AUTH_STATUSES, \
        f"Invalid authorization_status: {authorization_status}"
    assessment_id = _uuid()
    now = _now()
    conn.execute("""
        INSERT INTO assessment (
            assessment_id, target_id, assessment_date, start_time, end_time,
            tool_version, methodology_version, schema_version,
            scope, authorization_status, assessor, notes
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
    """, (assessment_id, target_id, now, start_time or now, end_time,
          tool_version, methodology_version, schema_version,
          scope, authorization_status, assessor, notes))
    conn.commit()
    return assessment_id


def get_assessment(conn, assessment_id):
    return conn.execute(
        "SELECT * FROM assessment WHERE assessment_id = ?", (assessment_id,)
    ).fetchone()


def list_assessments(conn, target_id=None):
    if target_id:
        return conn.execute(
            "SELECT * FROM assessment WHERE target_id = ? ORDER BY assessment_date",
            (target_id,)
        ).fetchall()
    return conn.execute(
        "SELECT * FROM assessment ORDER BY assessment_date"
    ).fetchall()


def close_assessment(conn, assessment_id):
    """Record end_time on an open assessment."""
    conn.execute(
        "UPDATE assessment SET end_time = ? WHERE assessment_id = ?",
        (_now(), assessment_id)
    )
    conn.commit()


# ── FINDING ──────────────────────────────────────────────────────────────────

def create_finding(conn, assessment_id, layer, check_id, status, description,
                   severity=None, confidence="HIGH", evidence=None,
                   recommendation=None, standard_ref=None,
                   taxonomy_id=None, check_version=None, detector_notes=None):
    """
    Record a raw finding observation.

    CRITICAL: NOT_APPLICABLE must be passed explicitly — callers must
    never convert NOT_APPLICABLE to PASS or FAIL before calling this.

    severity must be None when status is NOT_APPLICABLE or NOT_TESTED.
    """
    assert status in FINDING_STATUSES, f"Invalid status: {status}"
    assert layer in FINDING_LAYERS, f"Invalid layer: {layer}"
    if status in ("NOT_APPLICABLE", "NOT_TESTED") and severity is not None:
        raise ValueError(
            f"severity must be None when status is {status}, got {severity!r}"
        )
    finding_id = _uuid()
    conn.execute("""
        INSERT INTO finding (
            finding_id, assessment_id, layer, check_id, check_version,
            taxonomy_id, status, severity, confidence, description,
            evidence, recommendation, standard_ref, detector_notes, detected_at
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (finding_id, assessment_id, layer, check_id, check_version,
          taxonomy_id, status, severity, confidence, description,
          evidence, recommendation, standard_ref, detector_notes, _now()))
    conn.commit()
    return finding_id


def get_findings(conn, assessment_id):
    return conn.execute(
        "SELECT * FROM finding WHERE assessment_id = ? ORDER BY layer, severity",
        (assessment_id,)
    ).fetchall()


def get_findings_by_status(conn, assessment_id, status):
    assert status in FINDING_STATUSES
    return conn.execute(
        "SELECT * FROM finding WHERE assessment_id = ? AND status = ?",
        (assessment_id, status)
    ).fetchall()


def get_findings_by_layer(conn, layer):
    """Cross-assessment: all findings for a given layer. For research queries."""
    assert layer in FINDING_LAYERS
    return conn.execute(
        "SELECT * FROM finding WHERE layer = ? ORDER BY assessment_id",
        (layer,)
    ).fetchall()


def get_finding_prevalence(conn, check_id=None, layer=None):
    """
    Research query: count PASS/FAIL/NOT_APPLICABLE per check_id.
    NOT_APPLICABLE excluded from prevalence denominators.
    """
    where_clauses = ["status NOT IN ('NOT_APPLICABLE','NOT_TESTED','ERROR','UNKNOWN')"]
    params = []
    if check_id:
        where_clauses.append("check_id = ?")
        params.append(check_id)
    if layer:
        where_clauses.append("layer = ?")
        params.append(layer)
    where = " AND ".join(where_clauses)
    return conn.execute(f"""
        SELECT check_id, layer,
               COUNT(*) as total_applicable,
               SUM(CASE WHEN status='FAIL' THEN 1 ELSE 0 END) as fail_count,
               SUM(CASE WHEN status='PASS' THEN 1 ELSE 0 END) as pass_count,
               ROUND(100.0 * SUM(CASE WHEN status='FAIL' THEN 1 ELSE 0 END) / COUNT(*), 1) as fail_pct
        FROM finding
        WHERE {where}
        GROUP BY check_id, layer
        ORDER BY fail_pct DESC
    """, params).fetchall()


# ── SCORE SNAPSHOT ───────────────────────────────────────────────────────────

def create_score_snapshot(conn, assessment_id, composite_result,
                          scoring_model_id="weighted_composite_v1",
                          scoring_model_ver="1.0",
                          weight_os=0.30, weight_network=0.35, weight_web=0.35,
                          model_metadata=None, notes=None):
    """
    Persist a scoring snapshot derived from a completed assessment.
    Scores are derived artifacts — findings are the primary data.
    """
    import json
    snapshot_id = _uuid()
    layers = composite_result.get("layers", {})
    conn.execute("""
        INSERT INTO score_snapshot (
            snapshot_id, assessment_id, scoring_model_id, scoring_model_ver,
            os_score, network_score, web_score, composite_score,
            weight_os, weight_network, weight_web, weakest_layer,
            model_metadata, calculated_at, notes
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (snapshot_id, assessment_id, scoring_model_id, scoring_model_ver,
          layers.get("os_hardening", {}).get("score"),
          layers.get("network", {}).get("score"),
          layers.get("webapp", {}).get("score"),
          composite_result.get("composite_score"),
          weight_os, weight_network, weight_web,
          composite_result.get("weakest_layer"),
          json.dumps(model_metadata) if model_metadata else None,
          _now(), notes))
    conn.commit()
    return snapshot_id


def get_score_snapshots(conn, assessment_id):
    return conn.execute(
        "SELECT * FROM score_snapshot WHERE assessment_id = ? ORDER BY calculated_at",
        (assessment_id,)
    ).fetchall()


# ── REMEDIATION ──────────────────────────────────────────────────────────────

def create_remediation(conn, finding_id, recommendation, notes=None):
    """Create a pending remediation record for a finding."""
    remediation_id = _uuid()
    conn.execute("""
        INSERT INTO remediation (
            remediation_id, finding_id, recommendation, status, created_at, notes
        ) VALUES (?,?,?,?,?,?)
    """, (remediation_id, finding_id, recommendation, "PENDING", _now(), notes))
    conn.commit()
    return remediation_id


def update_remediation_status(conn, remediation_id, status,
                               remediation_date=None, effort_hours=None,
                               verification_assessment_id=None,
                               verification_result=None, notes=None):
    from db.schema import REMEDIATION_STATUSES
    assert status in REMEDIATION_STATUSES
    conn.execute("""
        UPDATE remediation SET
            status = ?,
            remediation_date = COALESCE(?, remediation_date),
            effort_hours = COALESCE(?, effort_hours),
            verification_assessment_id = COALESCE(?, verification_assessment_id),
            verification_result = COALESCE(?, verification_result),
            notes = COALESCE(?, notes)
        WHERE remediation_id = ?
    """, (status, remediation_date, effort_hours,
          verification_assessment_id, verification_result,
          notes, remediation_id))
    conn.commit()


def get_remediations(conn, finding_id):
    return conn.execute(
        "SELECT * FROM remediation WHERE finding_id = ? ORDER BY created_at",
        (finding_id,)
    ).fetchall()


# ── TAXONOMY HELPERS ─────────────────────────────────────────────────────────

def get_taxonomy_id(conn, category, subcategory=None):
    row = conn.execute(
        "SELECT taxonomy_id FROM taxonomy WHERE category=? AND (subcategory=? OR (subcategory IS NULL AND ? IS NULL))",
        (category, subcategory, subcategory)
    ).fetchone()
    return row["taxonomy_id"] if row else None
