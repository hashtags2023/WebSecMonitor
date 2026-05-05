"""
Directory & Path Enumeration
Checks for commonly exposed paths, admin panels, config files, and backups.
"""

import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

COMMON_PATHS = {
    # Admin panels
    "/admin": ("HIGH", "Admin panel exposed"),
    "/admin/login": ("HIGH", "Admin login exposed"),
    "/administrator": ("HIGH", "Admin panel exposed"),
    "/wp-admin": ("HIGH", "WordPress admin panel exposed"),
    "/phpmyadmin": ("CRITICAL", "phpMyAdmin panel exposed"),
    "/cpanel": ("HIGH", "cPanel exposed"),
    "/dashboard": ("MEDIUM", "Dashboard exposed"),
    "/manager": ("HIGH", "Manager panel exposed"),

    # Config & sensitive files
    "/.env": ("CRITICAL", "Environment file exposed — may contain credentials"),
    "/.git": ("CRITICAL", "Git repository exposed — source code may be accessible"),
    "/.git/config": ("CRITICAL", "Git config file exposed"),
    "/config.php": ("CRITICAL", "PHP config file exposed"),
    "/wp-config.php": ("CRITICAL", "WordPress config file exposed"),
    "/config.yml": ("HIGH", "YAML config file exposed"),
    "/config.json": ("HIGH", "JSON config file exposed"),
    "/database.yml": ("CRITICAL", "Database config file exposed"),
    "/settings.py": ("HIGH", "Python settings file exposed"),
    "/secrets.json": ("CRITICAL", "Secrets file exposed"),

    # Backup files
    "/backup": ("HIGH", "Backup directory exposed"),
    "/backup.zip": ("CRITICAL", "Backup zip file exposed"),
    "/backup.sql": ("CRITICAL", "SQL backup file exposed"),
    "/db_backup.sql": ("CRITICAL", "Database backup exposed"),
    "/www.zip": ("CRITICAL", "Site backup zip exposed"),

    # Common info pages
    "/robots.txt": ("INFO", "robots.txt found — check for sensitive paths"),
    "/sitemap.xml": ("INFO", "sitemap.xml found"),
    "/.well-known/security.txt": ("INFO", "security.txt found (good!)"),
    "/crossdomain.xml": ("MEDIUM", "crossdomain.xml found — check for overly permissive policy"),

    # Logs & debug
    "/logs": ("HIGH", "Logs directory exposed"),
    "/error.log": ("HIGH", "Error log exposed"),
    "/access.log": ("HIGH", "Access log exposed"),
    "/debug": ("HIGH", "Debug endpoint exposed"),
    "/phpinfo.php": ("CRITICAL", "phpinfo() page exposed — reveals server config"),
    "/server-status": ("HIGH", "Apache server-status exposed"),
    "/server-info": ("HIGH", "Apache server-info exposed"),

    # API endpoints
    "/api": ("INFO", "API root found"),
    "/api/v1": ("INFO", "API v1 found"),
    "/swagger": ("MEDIUM", "Swagger docs exposed"),
    "/swagger-ui.html": ("MEDIUM", "Swagger UI exposed"),
    "/api-docs": ("MEDIUM", "API docs exposed"),
    "/graphql": ("MEDIUM", "GraphQL endpoint exposed"),
}


def check_path(base_url: str, path: str, meta: tuple) -> dict | None:
    severity, description = meta
    url = base_url.rstrip("/") + path
    try:
        response = requests.get(
            url, timeout=6,
            headers={"User-Agent": "WebSecMonitor/1.0"},
            allow_redirects=False
        )
        if response.status_code in (200, 301, 302, 403):
            return {
                "path": path,
                "status_code": response.status_code,
                "severity": severity,
                "description": description,
                "url": url
            }
    except Exception:
        pass
    return None


def check_common_paths(target: str, verbose: bool = False) -> list:
    findings = []
    base_url = target.rstrip("/")
    total = len(COMMON_PATHS)

    if verbose:
        print(f"    [>] Testing {total} paths with threaded requests...")

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {
            executor.submit(check_path, base_url, path, meta): path
            for path, meta in COMMON_PATHS.items()
        }

        for future in as_completed(futures):
            result = future.result()
            if result:
                severity = result["severity"]
                status = result["status_code"]
                path = result["path"]
                description = result["description"]

                finding = {
                    "type": "Exposed Path / Directory",
                    "severity": severity,
                    "path": path,
                    "status_code": status,
                    "description": f"[HTTP {status}] {description}",
                    "recommendation": f"Restrict access to '{path}'. "
                                      "Remove or protect sensitive files and directories.",
                    "url": result["url"]
                }
                findings.append(finding)

                icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "INFO": "🔵"}.get(severity, "•")
                print(f"    {icon} [{severity}] [{status}] {path} — {description}")

    if not findings:
        print(f"    ✅ No common sensitive paths found")

    return findings
