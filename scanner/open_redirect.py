"""
Open Redirect Scanner
Tests for unvalidated redirect vulnerabilities in URL parameters.
"""

import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "//evil.com/%2F..",
    "https://evil.com/",
    "/\\evil.com",
    "https:evil.com",
    "/%09/evil.com",
    "//google.com@evil.com",
]

REDIRECT_PARAMS = [
    "redirect", "redirect_to", "redirect_url", "url", "next",
    "return", "return_to", "returnUrl", "goto", "target",
    "destination", "redir", "link", "continue", "forward"
]

EVIL_DOMAIN = "evil.com"


def inject_redirect(url: str, param: str, payload: str) -> str:
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [payload]
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def check_open_redirect(target: str, verbose: bool = False) -> list:
    findings = []
    parsed = urlparse(target)
    existing_params = parse_qs(parsed.query)

    # Combine existing params with common redirect param names
    params_to_test = list(existing_params.keys()) + REDIRECT_PARAMS

    tested_combos = set()

    for param in params_to_test:
        for payload in REDIRECT_PAYLOADS:
            combo = (param, payload)
            if combo in tested_combos:
                continue
            tested_combos.add(combo)

            test_url = inject_redirect(target, param, payload)

            try:
                response = requests.get(
                    test_url, timeout=8,
                    headers={"User-Agent": "WebSecMonitor/1.0"},
                    allow_redirects=False  # Don't follow redirects — we want to catch them
                )

                # Check if it's redirecting to our evil domain
                location = response.headers.get("Location", "")
                if response.status_code in (301, 302, 303, 307, 308) and EVIL_DOMAIN in location:
                    finding = {
                        "type": "Open Redirect",
                        "severity": "MEDIUM",
                        "parameter": param,
                        "payload": payload,
                        "description": f"Open redirect detected via parameter '{param}'. "
                                       f"Server redirected to: {location}",
                        "recommendation": "Validate redirect URLs against a whitelist of allowed domains. "
                                          "Never redirect to user-supplied URLs directly.",
                        "url": test_url
                    }
                    findings.append(finding)
                    print(f"    🟡 [MEDIUM] Open Redirect via param '{param}' → {location}")
                    if verbose:
                        print(f"        → Payload: {payload}")
                        print(f"        → Test URL: {test_url}")
                    break

                elif verbose and response.status_code in (301, 302, 303, 307, 308):
                    print(f"    [>] Redirect detected (to safe location): {location[:60]}")

            except requests.exceptions.Timeout:
                pass
            except Exception as e:
                if verbose:
                    print(f"    [>] Error testing redirect: {e}")

    if not findings:
        print(f"    ✅ No open redirects detected")

    return findings
