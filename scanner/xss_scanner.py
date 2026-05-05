"""
Cross-Site Scripting (XSS) Scanner
Tests URL parameters and forms for reflected XSS vulnerabilities.
"""

import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import re

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "'\"><script>alert('XSS')</script>",
    "<body onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "<iframe src=javascript:alert('XSS')>",
    "\"><img src=x onerror=alert(1)>",
    "';alert('XSS')//",
    "<script>document.write('XSS')</script>",
]

# Unique marker to detect reflection
MARKER = "WSMON_XSS_TEST_38291"


def inject_payload(url: str, param: str, payload: str) -> str:
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [payload]
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def check_reflection(url: str, param: str, verbose: bool) -> bool:
    """First check if input is reflected in the response (prerequisite for XSS)."""
    test_url = inject_payload(url, param, MARKER)
    try:
        resp = requests.get(test_url, timeout=8, headers={"User-Agent": "WebSecMonitor/1.0"})
        if MARKER in resp.text:
            if verbose:
                print(f"    [>] Param '{param}' reflects input in response — testing XSS payloads")
            return True
    except Exception:
        pass
    return False


def check_xss(target: str, verbose: bool = False) -> list:
    findings = []
    parsed = urlparse(target)
    params = parse_qs(parsed.query)

    if not params:
        test_url = target + ("&" if "?" in target else "?") + "search=test"
        params = {"search": ["test"]}
        target = test_url
        if verbose:
            print(f"    [>] No params found, using test param: {test_url}")

    for param in params:
        # First check if the param reflects at all
        reflects = check_reflection(target, param, verbose)

        if not reflects:
            if verbose:
                print(f"    [>] Param '{param}' does not reflect — skipping XSS payloads")
            continue

        for payload in XSS_PAYLOADS:
            test_url = inject_payload(target, param, payload)
            try:
                response = requests.get(
                    test_url, timeout=8,
                    headers={"User-Agent": "WebSecMonitor/1.0"},
                    allow_redirects=True
                )

                # Check if the raw payload appears unescaped in the response
                if payload in response.text:
                    finding = {
                        "type": "Cross-Site Scripting (XSS)",
                        "severity": "HIGH",
                        "parameter": param,
                        "payload": payload,
                        "description": f"Reflected XSS vulnerability detected in parameter '{param}'. "
                                       f"Payload was reflected unescaped in the response.",
                        "recommendation": "Encode all user-supplied output. Use Content-Security-Policy. "
                                          "Validate and sanitize all inputs server-side.",
                        "url": test_url
                    }
                    findings.append(finding)
                    print(f"    🟠 [HIGH] Reflected XSS in param '{param}' | Payload: {payload[:40]}")
                    if verbose:
                        print(f"        → Test URL: {test_url}")
                    break  # One finding per param is enough

            except requests.exceptions.Timeout:
                if verbose:
                    print(f"    [>] Timeout on payload test")
            except Exception as e:
                if verbose:
                    print(f"    [>] Error: {e}")

    if not findings:
        print(f"    ✅ No reflected XSS detected in tested parameters")

    return findings
