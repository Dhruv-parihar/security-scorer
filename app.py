#!/usr/bin/env python3
"""
Security Scorer — Web UI (Flask)
-----------------------------------
Phase 3: End-to-end research pipeline integration.
- Active network/web scan routes check authorization before scanning.
- Unauthorized requests receive a clear safe response; scanner not called.
- Authorized assessments are persisted via db/adapters.py.
- Existing UI/response behavior preserved.

Usage:
    python3 app.py
    Then open http://127.0.0.1:5000 in a browser.
"""

from flask import Flask, render_template, request
from modules import os_hardening, network_scan, webapp_scan, scoring
from modules.authorization import check_authorization
from modules.assessment_scope import validate_composite_scope
from db.schema import initialize, seed_taxonomy
from db.adapters import store_assessment_results
from db.repository import list_targets, create_target, add_target_identifier
from analysis.common import open_readonly
from analysis.longitudinal import run_longitudinal_analysis
from analysis.prevalence import run_full_analysis
import os

app = Flask(__name__)

DB_PATH = os.path.join(os.path.dirname(__file__), "research.db")


def _get_db():
    """Open and return an initialized DB connection."""
    conn, _ = initialize(DB_PATH)
    seed_taxonomy(conn)
    return conn


@app.route("/", methods=["GET"])
def index():
    conn = _get_db()
    targets = list_targets(conn)
    conn.close()
    return render_template("index.html", targets=targets)


@app.route("/research", methods=["GET"])
def research_dashboard():
    """Show aggregate research summaries without opening the DB for writes."""
    if not os.path.isfile(DB_PATH):
        return render_template("research_dashboard.html", dashboard=None, error=None)

    conn = None
    try:
        conn = open_readonly(DB_PATH)
        analysis = run_full_analysis(conn)
        longitudinal = run_longitudinal_analysis(conn)
        dashboard = {
            "assessment_distribution": analysis["assessment_distribution"],
            "layer_prevalence": analysis["layer_prevalence"],
            "finding_prevalence": analysis["finding_prevalence"][:10],
            "severity_distribution": analysis["severity_distribution"],
            "status_distribution": analysis["status_distribution"],
            "empirical_limitation": analysis["empirical_limitation"],
            "longitudinal": {
                "target_count": longitudinal["target_count"],
                "comparison_count": longitudinal["comparison_count"],
            },
        }
        return render_template("research_dashboard.html", dashboard=dashboard, error=None)
    except Exception as exc:
        # Analysis is read-only; surface malformed or incompatible DBs clearly.
        return render_template("research_dashboard.html", dashboard=None, error=str(exc)), 500
    finally:
        if conn is not None:
            conn.close()


@app.route("/targets/add", methods=["POST"])
def add_target():
    """Add a new authorized target record."""
    conn = _get_db()
    errors = []
    try:
        create_target(
            conn,
            alias=request.form.get("alias", "").strip(),
            target_type=request.form.get("target_type", "lab_vm").strip(),
            environment=request.form.get("environment", "lab").strip(),
            authorization_status=request.form.get("authorization_status", "LAB").strip(),
            os_family=request.form.get("os_family", "unknown").strip() or None,
            os_name=request.form.get("os_name", "").strip() or None,
            authorization_ref=request.form.get("authorization_ref", "").strip() or None,
        )
    except Exception as e:
        errors.append(f"Could not add target: {e}")
    targets = list_targets(conn)
    conn.close()
    return render_template("index.html", targets=targets, errors=errors)


@app.route("/targets/identifiers/add", methods=["POST"])
def add_target_identifier_route():
    """Link an additional explicitly authorized scan identifier to one target."""
    conn = _get_db()
    errors = []
    try:
        add_target_identifier(
            conn,
            target_id=request.form.get("target_id", "").strip(),
            identifier=request.form.get("identifier", "").strip(),
            notes=request.form.get("identifier_notes", "").strip() or None,
        )
    except Exception as e:
        errors.append(f"Could not link target identifier: {e}")
    targets = list_targets(conn)
    conn.close()
    return render_template("index.html", targets=targets, errors=errors)


@app.route("/scan", methods=["POST"])
def scan():
    layers_selected = request.form.getlist("layers")
    network_target = request.form.get("network_target", "").strip()
    webapp_target = request.form.get("webapp_target", "").strip()

    layer_results = {}
    errors = []
    auth_blocks = []
    target_ids = {}

    conn = _get_db()

    # ── OS Hardening (no network target — no authorization check required) ──
    if "os_hardening" in layers_selected:
        layer_results["os_hardening"] = os_hardening.run()

    # ── Network scan — authorization required ────────────────────────────────
    if "network" in layers_selected:
        if not network_target:
            errors.append("Network scan selected but no target IP provided.")
        else:
            authorized, tid, message = check_authorization(conn, network_target)
            if not authorized:
                auth_blocks.append(
                    f"Network scan blocked for '{network_target}': {message}"
                )
            else:
                target_ids["network"] = tid
                result = network_scan.run(network_target)
                if result.get("error"):
                    errors.append(f"Network scan: {result['error']}")
                else:
                    layer_results["network"] = result

    # ── Web app scan — authorization required ────────────────────────────────
    if "webapp" in layers_selected:
        if not webapp_target:
            errors.append("Web app scan selected but no target URL provided.")
        else:
            authorized, tid, message = check_authorization(conn, webapp_target)
            if not authorized:
                auth_blocks.append(
                    f"Web scan blocked for '{webapp_target}': {message}"
                )
            else:
                target_ids["webapp"] = tid
                result = webapp_scan.run(webapp_target)
                if result.get("scan_error"):
                    errors.append(f"Web app scan: {result['scan_error']}")
                if result.get("score") is not None or result.get("findings"):
                    layer_results["webapp"] = result

    # ── Composite scoring ────────────────────────────────────────────────────
    scope_error, target_id = validate_composite_scope(layer_results, target_ids)
    if scope_error:
        errors.append(scope_error)
        composite = scoring.compute_composite({})
    else:
        composite = scoring.compute_composite(layer_results)

    # ── Persist to research DB ───────────────────────────────────────────────
    assessment_id = None
    if target_id and layer_results and not scope_error:
        try:
            assessment_id = store_assessment_results(
                conn, target_id, layer_results, composite
            )
        except Exception as e:
            errors.append(f"DB persistence warning: {e}")

    conn.close()

    return render_template(
        "results.html",
        composite=composite,
        layer_results=layer_results,
        errors=errors,
        auth_blocks=auth_blocks,
        assessment_id=assessment_id,
    )


if __name__ == "__main__":
    app.run(debug=False, host="127.0.0.1", port=5000)
