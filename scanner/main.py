#!/usr/bin/env python3
"""
WebSecMonitor - Web Vulnerability Scanner
Author: hashtags2023
Description: Scans web targets for common vulnerabilities including
             XSS, SQL Injection, open redirects, missing headers, and more.
"""

import argparse
import sys
from datetime import datetime
from scanner.header_checker import check_security_headers
from scanner.sqli_scanner import check_sqli
from scanner.xss_scanner import check_xss
from scanner.open_redirect import check_open_redirect
from scanner.dir_enum import check_common_paths
from utils.report import generate_report
from utils.banner import print_banner


def run_scan(target: str, output: str = None, verbose: bool = False):
    print_banner()
    print(f"\n[*] Target       : {target}")
    print(f"[*] Scan started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"[*] Mode         : {'Verbose' if verbose else 'Standard'}\n")
    print("-" * 60)

    results = {
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "findings": []
    }

    # --- Security Headers ---
    print("\n[+] Checking Security Headers...")
    header_findings = check_security_headers(target, verbose)
    results["findings"].extend(header_findings)

    # --- SQL Injection ---
    print("\n[+] Testing for SQL Injection...")
    sqli_findings = check_sqli(target, verbose)
    results["findings"].extend(sqli_findings)

    # --- XSS ---
    print("\n[+] Testing for Cross-Site Scripting (XSS)...")
    xss_findings = check_xss(target, verbose)
    results["findings"].extend(xss_findings)

    # --- Open Redirect ---
    print("\n[+] Testing for Open Redirect...")
    redirect_findings = check_open_redirect(target, verbose)
    results["findings"].extend(redirect_findings)

    # --- Directory Enumeration ---
    print("\n[+] Checking for Exposed Paths & Directories...")
    dir_findings = check_common_paths(target, verbose)
    results["findings"].extend(dir_findings)

    # --- Summary ---
    print("\n" + "=" * 60)
    critical = [f for f in results["findings"] if f["severity"] == "CRITICAL"]
    high     = [f for f in results["findings"] if f["severity"] == "HIGH"]
    medium   = [f for f in results["findings"] if f["severity"] == "MEDIUM"]
    info     = [f for f in results["findings"] if f["severity"] == "INFO"]

    print(f"\n[SCAN COMPLETE] Results for: {target}")
    print(f"  🔴 Critical : {len(critical)}")
    print(f"  🟠 High     : {len(high)}")
    print(f"  🟡 Medium   : {len(medium)}")
    print(f"  🔵 Info     : {len(info)}")
    print(f"  Total       : {len(results['findings'])} findings\n")

    if output:
        generate_report(results, output)
        print(f"[*] Report saved to: {output}")

    return results


def main():
    parser = argparse.ArgumentParser(
        description="WebSecMonitor - Web Vulnerability Scanner",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("target", help="Target URL (e.g. http://testphp.vulnweb.com)")
    parser.add_argument("-o", "--output", help="Save report to file (e.g. report.json)", default=None)
    parser.add_argument("-v", "--verbose", help="Enable verbose output", action="store_true")

    args = parser.parse_args()

    if not args.target.startswith("http"):
        print("[!] Error: Target must start with http:// or https://")
        sys.exit(1)

    run_scan(args.target, args.output, args.verbose)


if __name__ == "__main__":
    main()
