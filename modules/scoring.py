"""
Composite Scoring Engine
--------------------------
Combines OS Hardening, Network, and Web Application layer scores into
a single weighted composite score, and produces a ranked list of
recommendations prioritized by severity across all layers.

This module is the core contribution of the framework: rather than
treating each security layer in isolation, it aggregates them into one
risk picture and tells the user which layer to fix first.
"""

# Default layer weights — how much each layer contributes to the
# composite score. Adjust these based on the threat model you care
# about (e.g. a public-facing web server might weight webapp higher).
DEFAULT_WEIGHTS = {
    "os_hardening": 0.3,
    "network": 0.35,
    "webapp": 0.35,
}

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def compute_composite(layer_results, weights=None):
    """
    layer_results: dict like
        {
            "os_hardening": {...result from os_hardening.run()...},
            "network": {...result from network_scan.run()...},
            "webapp": {...result from webapp_scan.run()...},
        }
    Only layers actually present in layer_results are included/reweighted.
    """
    weights = weights or DEFAULT_WEIGHTS
    present_layers = {k: v for k, v in layer_results.items() if v is not None}

    if not present_layers:
        return {"composite_score": None, "layers": {}, "recommendations": []}

    # Re-normalize weights across only the layers that were actually run
    total_weight = sum(weights.get(layer, 0) for layer in present_layers)
    composite = 0
    layer_summary = {}

    for layer, result in present_layers.items():
        layer_weight = weights.get(layer, 0) / total_weight if total_weight else 0
        layer_score = result.get("score", 0)
        composite += layer_score * layer_weight
        layer_summary[layer] = {
            "score": layer_score,
            "weight_used": round(layer_weight, 2),
        }

    composite = round(composite)

    # Identify the weakest layer — this drives the "fix this first" message
    weakest_layer = min(layer_summary, key=lambda l: layer_summary[l]["score"])

    # Build a single ranked recommendation list across all layers,
    # sorted by severity (critical first) regardless of which layer
    # the finding came from.
    all_recommendations = []
    for layer, result in present_layers.items():
        for finding in result.get("findings", []):
            if not finding.get("passed", True):
                all_recommendations.append({
                    "layer": layer,
                    "severity": finding.get("severity", "low"),
                    "description": finding.get("description")
                        or finding.get("note")
                        or finding.get("id"),
                    "recommendation": finding.get("recommendation"),
                })

    all_recommendations.sort(key=lambda r: SEVERITY_RANK.get(r["severity"], 3))

    return {
        "composite_score": composite,
        "layers": layer_summary,
        "weakest_layer": weakest_layer,
        "recommendations": all_recommendations,
    }
