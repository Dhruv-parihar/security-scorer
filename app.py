#!/usr/bin/env python3
"""
Security Scorer — Web UI (Flask)
-----------------------------------
Same engine as main.py, wrapped in a simple web interface.

Usage:
    python3 app.py
    Then open http://127.0.0.1:5000 in a browser.
"""

from flask import Flask, render_template, request
from modules import os_hardening, network_scan, webapp_scan, scoring

app = Flask(__name__)


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    layers_selected = request.form.getlist("layers")
    network_target = request.form.get("network_target", "").strip()
    webapp_target = request.form.get("webapp_target", "").strip()

    layer_results = {}
    errors = []

    if "os_hardening" in layers_selected:
        layer_results["os_hardening"] = os_hardening.run()

    if "network" in layers_selected:
        if network_target:
            result = network_scan.run(network_target)
            if result.get("error"):
                errors.append(f"Network scan: {result['error']}")
            else:
                layer_results["network"] = result
        else:
            errors.append("Network scan selected but no target IP provided.")

    if "webapp" in layers_selected:
        if webapp_target:
            result = webapp_scan.run(webapp_target)
            if result.get("error"):
                errors.append(f"Web app scan: {result['error']}")
            else:
                layer_results["webapp"] = result
        else:
            errors.append("Web app scan selected but no target URL provided.")

    composite = scoring.compute_composite(layer_results)

    return render_template(
        "results.html",
        composite=composite,
        layer_results=layer_results,
        errors=errors,
    )


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
