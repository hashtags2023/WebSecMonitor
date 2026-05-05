"""
Security Headers Checker
Checks for missing or misconfigured HTTP security headers.
"""

import requests
from urllib.parse import urlparse

REQUIRED_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "HIGH",
        "description": "HSTS not set. Site may be vulnerable to SSL stripping attacks.",
        "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"
    },
    "Content-Security-Policy": {
        "severity": "HIGH",
        "description": "No Content Security Policy detected. XSS attacks may be easier to execute.",
        "recommendation": "Define a strict CSP header to restrict resource loading."
    },
    "X-Frame-Options": {
        "severity": "MEDIUM",
        "description": "X-Frame-Options missing. Site may be vulnerable to clickjacking.",
        "recommendation": "Add: X-Frame-Options: DENY or SAMEORIGIN"
    },
    "X-Content-Type-Options": {
        "severity": "MEDIUM",
        "description": "X-Content-Type-Options missing. Browser may MIME-sniff responses.",
        "recommendation": "Add: X-Content-Type-Options: nosniff"
    },
    "Referrer-Policy": {
        "severity": "INFO",
        "description": "Referrer-Policy not set. May leak sensitive URL info in referrer headers.",
        "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin"
    },
    "Permissions-Policy": {
        "severity": "INFO",
        "description": "Permissions-Policy not set. Browser features not restricted.",
        "recommendation": "Add a Permissions-Policy header to restrict access to browser APIs."
    },
    "X-XSS-Protection": {
        "severity": "INFO",
        "description": "X-XSS-Protection header missing (legacy, but still useful for older browsers).",
        "recommendation": "Add: X-XSS-Protection: 1; mode=block"
    }
}

INSECURE_HEADERS = {
    "Server": "Exposes server software version. Remove or sanitize this header.",
    "X-Powered-By": "Exposes backend technology. Remove this header.",
    "X-AspNet-Version": "Exposes ASP.NET version. Remove this header."
}


def check_security_headers(target: str, verbose: bool = False) -> list:
    findings = []

    try:
        response = requests.get(target, timeout=10, allow_redirects=True,
                                headers={"User-Agent": "WebSecMonitor/1.0"})
        headers = response.headers

        if verbose:
            print(f"    [>] Received {len(headers)} response headers")

        # Check missing security headers
        for header, meta in REQUIRED_HEADERS.items():
            if header not in headers:
                finding = {
                    "type": "Missing Security Header",
                    "name": header,
                    "severity": meta["severity"],
                    "description": meta["description"],
                    "recommendation": meta["recommendation"],
                    "url": target
                }
                findings.append(finding)
                severity_icon = {"HIGH": "🟠", "MEDIUM": "🟡", "INFO": "🔵"}.get(meta["severity"], "•")
                print(f"    {severity_icon} [{meta['severity']}] Missing: {header}")
                if verbose:
                    print(f"        → {meta['description']}")
            else:
                if verbose:
                    print(f"    ✅ Found: {header}: {headers[header][:60]}")

        # Check for information-leaking headers
        for header, description in INSECURE_HEADERS.items():
            if header in headers:
                finding = {
                    "type": "Information Disclosure Header",
                    "name": header,
                    "value": headers[header],
                    "severity": "MEDIUM",
                    "description": f"Header '{header}: {headers[header]}' is present. {description}",
                    "recommendation": f"Remove or sanitize the '{header}' header.",
                    "url": target
                }
                findings.append(finding)
                print(f"    🟡 [MEDIUM] Info Leak Header: {header}: {headers[header]}")

        # Check HTTPS
        if urlparse(target).scheme == "http":
            findings.append({
                "type": "Insecure Protocol",
                "name": "HTTP Used",
                "severity": "CRITICAL",
                "description": "Target is using HTTP instead of HTTPS. All traffic is unencrypted.",
                "recommendation": "Enforce HTTPS and redirect all HTTP traffic.",
                "url": target
            })
            print(f"    🔴 [CRITICAL] Site is using HTTP (not HTTPS)")

    except requests.exceptions.ConnectionError:
        print(f"    [!] Could not connect to {target}")
    except requests.exceptions.Timeout:
        print(f"    [!] Connection timed out for {target}")
    except Exception as e:
        print(f"    [!] Error checking headers: {e}")

    return findings
