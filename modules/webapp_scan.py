"""
Web Application Vulnerability Scan Module
-------------------------------------------
Generic, lightweight checks against a target URL:
  - Security headers (CSP, X-Frame-Options, HSTS, X-Content-Type-Options)
  - Cookie flags (HttpOnly, Secure)
  - Basic reflected SQL-injection heuristic on URL query parameters
  - Basic reflected XSS heuristic on URL query parameters

This is a heuristic scanner for educational/lab use against systems you
own or have explicit permission to test (e.g. DVWA on Metasploitable).
It is not a replacement for tools like Burp Suite or OWASP ZAP.
"""

import urllib.parse
import requests

SQLI_PAYLOAD = "' OR '1'='1"
XSS_PAYLOAD = "<script>alert(1)</script>"

SECURITY_HEADERS = {
    "Content-Security-Policy": "medium",
    "X-Frame-Options": "medium",
    "Strict-Transport-Security": "low",
    "X-Content-Type-Options": "low",
}

SEVERITY_WEIGHT = {
    "critical": 40,
    "high": 25,
    "medium": 10,
    "low": 5,
}


def _check_headers(response):
    findings = []
    for header, severity in SECURITY_HEADERS.items():
        present = header in response.headers
        findings.append({
            "id": f"header_{header.lower().replace('-', '_')}",
            "description": f"'{header}' header is set",
            "passed": present,
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
            "severity": "medium",
            "recommendation": f"Set HttpOnly flag on cookie '{cookie.name}'",
        })
        findings.append({
            "id": f"cookie_{cookie.name}_secure",
            "description": f"Cookie '{cookie.name}' has Secure flag",
            "passed": bool(has_secure),
            "severity": "medium",
            "recommendation": f"Set Secure flag on cookie '{cookie.name}'",
        })
    return findings


def _inject_param(url, payload):
    """Return a version of url with payload appended to each query param."""
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)
    if not params:
        return None
    injected = {k: v[0] + payload for k, v in params.items()}
    new_query = urllib.parse.urlencode(injected)
    return urllib.parse.urlunparse(parsed._replace(query=new_query))


def _check_sqli(url, session):
    test_url = _inject_param(url, SQLI_PAYLOAD)
    if not test_url:
        return None
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
            "severity": "critical",
            "recommendation": "Use parameterized queries; investigate this endpoint manually",
        }
    except requests.RequestException:
        return None


def _check_xss(url, session):
    test_url = _inject_param(url, XSS_PAYLOAD)
    if not test_url:
        return None
    try:
        resp = session.get(test_url, timeout=10)
        reflected = XSS_PAYLOAD in resp.text
        return {
            "id": "reflected_xss_heuristic",
            "description": "Injected script payload is not reflected unescaped",
            "passed": not reflected,
            "severity": "high",
            "recommendation": "Escape/encode user input before rendering it in HTML",
        }
    except requests.RequestException:
        return None


def run(target_url):
    findings = []
    session = requests.Session()

    try:
        response = session.get(target_url, timeout=10)
    except requests.RequestException as e:
        return {
            "layer": "webapp",
            "score": 0,
            "findings": [],
            "error": f"Could not reach target URL: {e}",
        }

    findings.extend(_check_headers(response))
    findings.extend(_check_cookies(response))

    sqli_result = _check_sqli(target_url, session)
    if sqli_result:
        findings.append(sqli_result)

    xss_result = _check_xss(target_url, session)
    if xss_result:
        findings.append(xss_result)

    total_penalty = sum(
        SEVERITY_WEIGHT.get(f["severity"], 5)
        for f in findings if not f["passed"]
    )
    score = max(0, 100 - total_penalty)

    return {
        "layer": "webapp",
        "score": score,
        "findings": findings,
    }


if __name__ == "__main__":
    import sys
    import json
    target = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1/"
    print(json.dumps(run(target), indent=2))
