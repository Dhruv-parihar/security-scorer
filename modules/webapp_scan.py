"""
Web Application Security Checks
--------------------------------
Bounded checks against a specifically authorized URL:
  - Security headers and cookie flags
  - TLS certificate validation and negotiated protocol (HTTPS URLs)
  - Basic reflected SQL-injection and XSS heuristics

This is an educational/lab scanner, not a replacement for Burp Suite or ZAP.
TLS validation uses the platform trust store and never disables verification.
Legacy protocol/cipher enumeration is intentionally out of scope; a failed
handshake is recorded as ERROR unless certificate verification specifically
fails, so inability to inspect is not silently classified as a vulnerability.
"""

import socket
import ssl
import urllib.parse

import requests

from modules.scoring_config import (
    WEB_SEVERITY_WEIGHT as SEVERITY_WEIGHT,
    WEB_TLS_CHECK_VERSION,
)

SQLI_PAYLOAD = "' OR '1'='1"
XSS_PAYLOAD = "<script>alert(1)</script>"

SECURITY_HEADERS = {
    "Content-Security-Policy": "medium",
    "X-Frame-Options": "medium",
    "Strict-Transport-Security": "low",
    "X-Content-Type-Options": "low",
}


def _finding(check_id, description, status, severity=None, recommendation=None,
             evidence=None, check_version=None):
    passed = True if status == "PASS" else False if status == "FAIL" else None
    return {
        "id": check_id,
        "description": description,
        "status": status,
        "passed": passed,
        "severity": severity if status in ("PASS", "FAIL") else None,
        "recommendation": recommendation,
        "evidence": evidence,
        "check_version": check_version,
    }


def _unevaluated(check_id, status, reason, check_version=None):
    return _finding(check_id, reason, status, check_version=check_version)


def _check_tls(target_url):
    """Check HTTPS use, certificate trust, and the negotiated TLS version."""
    transport_id = "https_transport"
    certificate_id = "tls_certificate_valid"
    protocol_id = "tls_protocol_version"
    version = WEB_TLS_CHECK_VERSION
    try:
        parsed = urllib.parse.urlparse(target_url)
        hostname = parsed.hostname
        port = parsed.port or 443
    except ValueError:
        reason = "The supplied URL or port is invalid."
        return [
            _unevaluated(transport_id, "ERROR", reason, version),
            _unevaluated(certificate_id, "ERROR", reason, version),
            _unevaluated(protocol_id, "ERROR", reason, version),
        ]

    if parsed.scheme.lower() == "http":
        return [
            _finding(
                transport_id, "Target URL uses HTTPS transport", "FAIL", "high",
                "Serve the application over HTTPS and redirect HTTP to HTTPS",
                evidence="The supplied scan URL uses the HTTP scheme.",
                check_version=version,
            ),
            _unevaluated(certificate_id, "NOT_APPLICABLE",
                         "No TLS certificate is presented over the supplied HTTP URL.", version),
            _unevaluated(protocol_id, "NOT_APPLICABLE",
                         "No TLS protocol is negotiated over the supplied HTTP URL.", version),
        ]

    if parsed.scheme.lower() != "https" or not hostname:
        reason = "A valid HTTP or HTTPS URL with a hostname is required."
        return [
            _unevaluated(transport_id, "ERROR", reason, version),
            _unevaluated(certificate_id, "ERROR", reason, version),
            _unevaluated(protocol_id, "ERROR", reason, version),
        ]

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as raw_socket:
            with context.wrap_socket(raw_socket, server_hostname=hostname) as tls_socket:
                negotiated = tls_socket.version()
        if negotiated is None:
            raise ssl.SSLError("TLS protocol could not be determined")
        protocol_passed = negotiated in ("TLSv1.2", "TLSv1.3")
        protocol_finding = _finding(
            protocol_id,
            "Negotiated TLS protocol is version 1.2 or newer",
            "PASS" if protocol_passed else "FAIL",
            "high",
            None if protocol_passed else "Configure TLS 1.2 or TLS 1.3 and disable older protocols",
            evidence=f"Negotiated protocol: {negotiated}",
            check_version=version,
        )
        return [
            _finding(transport_id, "Target URL uses HTTPS transport", "PASS", "high",
                     evidence="A certificate-verified TLS handshake succeeded.", check_version=version),
            _finding(certificate_id, "TLS certificate validates against the system trust store", "PASS", "high",
                     evidence="Certificate verification succeeded using the platform trust store.", check_version=version),
            protocol_finding,
        ]
    except ssl.SSLCertVerificationError:
        return [
            _unevaluated(transport_id, "ERROR", "TLS handshake did not complete because certificate validation failed.", version),
            _finding(certificate_id, "TLS certificate validates against the system trust store", "FAIL", "high",
                     "Install a valid certificate for this hostname from a trusted issuer",
                     evidence="Certificate verification failed under the platform trust store.", check_version=version),
            _unevaluated(protocol_id, "ERROR", "TLS protocol could not be evaluated because certificate validation failed.", version),
        ]
    except (ssl.SSLError, OSError, ValueError) as exc:
        reason = f"TLS handshake could not be evaluated ({type(exc).__name__})."
        return [
            _unevaluated(transport_id, "ERROR", reason, version),
            _unevaluated(certificate_id, "ERROR", reason, version),
            _unevaluated(protocol_id, "ERROR", reason, version),
        ]


def _check_headers(response):
    findings = []
    final_scheme = urllib.parse.urlparse(getattr(response, "url", "")).scheme.lower()
    for header, severity in SECURITY_HEADERS.items():
        check_id = f"header_{header.lower().replace('-', '_')}"
        if header == "Strict-Transport-Security" and final_scheme != "https":
            findings.append(_unevaluated(
                check_id, "NOT_APPLICABLE",
                "HSTS is evaluated only on an HTTPS response.",
            ))
            continue
        present = header in response.headers
        findings.append({
            "id": check_id,
            "description": f"'{header}' header is set",
            "passed": present,
            "status": "PASS" if present else "FAIL",
            "severity": severity,
            "recommendation": f"Add the '{header}' response header",
        })
    return findings


def _check_cookies(response):
    findings = []
    for cookie in response.cookies:
        has_httponly = cookie.has_nonstandard_attr("HttpOnly") or getattr(cookie, "_rest", {}).get("HttpOnly", False)
        has_secure = cookie.secure
        findings.append({
            "id": f"cookie_{cookie.name}_httponly",
            "description": f"Cookie '{cookie.name}' has HttpOnly flag",
            "passed": bool(has_httponly),
            "status": "PASS" if has_httponly else "FAIL",
            "severity": "medium",
            "recommendation": f"Set HttpOnly flag on cookie '{cookie.name}'",
        })
        findings.append({
            "id": f"cookie_{cookie.name}_secure",
            "description": f"Cookie '{cookie.name}' has Secure flag",
            "passed": bool(has_secure),
            "status": "PASS" if has_secure else "FAIL",
            "severity": "medium",
            "recommendation": f"Set Secure flag on cookie '{cookie.name}'",
        })
    return findings


def _inject_param(url, payload):
    """Return a URL with payload appended to each query parameter."""
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)
    if not params:
        return None
    injected = {key: values[0] + payload for key, values in params.items()}
    new_query = urllib.parse.urlencode(injected)
    return urllib.parse.urlunparse(parsed._replace(query=new_query))


def _check_sqli(url, session):
    test_url = _inject_param(url, SQLI_PAYLOAD)
    if not test_url:
        return _unevaluated("reflected_sqli_heuristic", "NOT_TESTED", "No query parameters to test")
    try:
        resp = session.get(test_url, timeout=10)
        suspicious = any(
            keyword in resp.text.lower()
            for keyword in ["sql syntax", "mysql_fetch", "you have an error in your sql", "warning: mysql"]
        )
        return {
            "id": "reflected_sqli_heuristic",
            "description": "No SQL error/behavior change from injected payload",
            "passed": not suspicious,
            "status": "PASS" if not suspicious else "FAIL",
            "severity": "critical",
            "recommendation": "Use parameterized queries; investigate this endpoint manually",
        }
    except requests.RequestException:
        return _unevaluated("reflected_sqli_heuristic", "ERROR", "Probe request failed")


def _check_xss(url, session):
    test_url = _inject_param(url, XSS_PAYLOAD)
    if not test_url:
        return _unevaluated("reflected_xss_heuristic", "NOT_TESTED", "No query parameters to test")
    try:
        resp = session.get(test_url, timeout=10)
        reflected = XSS_PAYLOAD in resp.text
        return {
            "id": "reflected_xss_heuristic",
            "description": "Injected script payload is not reflected unescaped",
            "passed": not reflected,
            "status": "PASS" if not reflected else "FAIL",
            "severity": "high",
            "recommendation": "Escape/encode user input before rendering it in HTML",
        }
    except requests.RequestException:
        return _unevaluated("reflected_xss_heuristic", "ERROR", "Probe request failed")


def _score(findings):
    evaluated = [finding for finding in findings if finding.get("status") in ("PASS", "FAIL")]
    if not evaluated:
        return None
    total_penalty = sum(
        SEVERITY_WEIGHT.get(finding.get("severity"), 5)
        for finding in evaluated if finding["status"] == "FAIL"
    )
    return max(0, 100 - total_penalty)


def run(target_url):
    findings = _check_tls(target_url)
    session = requests.Session()
    scan_error = None
    try:
        response = session.get(target_url, timeout=10)
    except requests.RequestException as exc:
        response = None
        scan_error = f"Could not retrieve the web response ({type(exc).__name__})."

    if response is not None:
        findings.extend(_check_headers(response))
        findings.extend(_check_cookies(response))
        findings.extend((_check_sqli(target_url, session), _check_xss(target_url, session)))
    else:
        findings.extend((
            _unevaluated("reflected_sqli_heuristic", "NOT_TESTED", "Base page unavailable; probe not run."),
            _unevaluated("reflected_xss_heuristic", "NOT_TESTED", "Base page unavailable; probe not run."),
        ))

    result = {"layer": "webapp", "score": _score(findings), "findings": findings}
    if scan_error:
        result["scan_error"] = scan_error
    return result


if __name__ == "__main__":
    import json
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1/"
    print(json.dumps(run(target), indent=2))
