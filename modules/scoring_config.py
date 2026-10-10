"""Versioned scoring parameters. Preserve historical layer-specific penalties."""
SCORING_MODEL_VERSION = '1.2'
SEVERITY_CONFIG_VERSION = '1.1'
OS_SCORING_METHOD = 'severity_weighted_normalized_v1'
OS_SEVERITY_WEIGHT = {'high': 3, 'medium': 2, 'low': 1}
WEB_TLS_CHECK_VERSION = '1.0'
DEFAULT_WEIGHTS = {'os_hardening': 0.30, 'network': 0.35, 'webapp': 0.35}
NETWORK_SEVERITY_WEIGHT = {'critical': 40, 'high': 25, 'medium': 10, 'low': 2}
WEB_SEVERITY_WEIGHT = {'critical': 40, 'high': 25, 'medium': 10, 'low': 5}
SEVERITY_RANK = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'informational': 4}
