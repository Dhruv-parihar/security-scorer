"""Versioned scoring parameters. Preserve historical layer-specific penalties."""
SCORING_MODEL_VERSION = '1.1'
SEVERITY_CONFIG_VERSION = '1.0'
DEFAULT_WEIGHTS = {'os_hardening': 0.30, 'network': 0.35, 'webapp': 0.35}
NETWORK_SEVERITY_WEIGHT = {'critical': 40, 'high': 25, 'medium': 10, 'low': 2}
WEB_SEVERITY_WEIGHT = {'critical': 40, 'high': 25, 'medium': 10, 'low': 5}
SEVERITY_RANK = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'informational': 4}
