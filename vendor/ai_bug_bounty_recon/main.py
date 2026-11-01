import argparse
import sys
import time
from datetime import datetime

from core.recon_core import run_recon
from ai_engine.exploit_generator import generate_exploit
from reports.report_generator import generate_report
from utils import logger

# ===============================================
# SUMMARY PRINTER
# ===============================================

def print_summary(results):
    """Print a clean summary of all scan results."""

    domain    = results.get("domain", "unknown")
    risk      = results.get("risk", {})
    findings  = results.get("findings", [])
    endpoints = results.get("endpoints", [])

    print("\n" + "=" * 60)
    print(f"  SCAN SUMMARY — {domain}")
    print("=" * 60)

    print(f"\n  Subdomains      : {len(results.get('subdomains', []))}")
    print(f"  Alive Hosts     : {len(results.get('live_hosts', []))}")
    print(f"  Endpoints       : {len(endpoints)}")
    print(f"  JS Files        : {len(results.get('js_files', []))}")
    print(f"  JS Intel Hits   : {len(results.get('js_intelligence', []))}")
    print(f"  Directories     : {len(results.get('directories', []))}")
    print(f"  Findings        : {len(findings)}")
    print(f"  Exploits        : {len(results.get('exploits', []))}")

    critical = len(risk.get("critical", []))
    high     = len(risk.get("high", []))
    medium   = len(risk.get("medium", []))
    low      = len(risk.get("low", []))

    print(f"\n  Risk Breakdown:")
    if critical: print(f"    Critical : {critical}")
    if high:     print(f"    High     : {high}")
    if medium:   print(f"    Medium   : {medium}")
    if low:      print(f"    Low      : {low}")

    if not (critical or high or medium or low):
        print("    No findings")

    print()


def print_section(title, items, formatter=None, limit=20):
    """Print a labeled section with optional item limit."""
    print(f"\n{'─' * 50}")
    print(f"  {title} ({len(items)} total)")
    print(f"{'─' * 50}")

    for item in items[:limit]:
        if formatter:
            print(f"  {formatter(item)}")
        elif isinstance(item, dict):
            print(f"  {item}")
        else:
            print(f"  {item}")

    if len(items) > limit:
        print(f"  ... and {len(items) - limit} more")


# ===============================================
# ARGUMENT PARSER
# ===============================================

def parse_args():
    parser = argparse.ArgumentParser(
        description="AI Bug Bounty Recon — Automated VAPT Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py -d example.com
  python main.py -d example.com --no-report
  python main.py -d example.com --no-payloads --verbose
        """
    )

    parser.add_argument(
        "-d", "--domain",
        help="Target domain (e.g. example.com)"
    )
    parser.add_argument(
        "--no-report",
        action="store_true",
        help="Skip PDF report generation"
    )
    parser.add_argument(
        "--no-payloads",
        action="store_true",
        help="Skip payload suggestions"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print full results for each section"
    )
    parser.add_argument(
        "--output-dir",
        default="reports",
        help="Directory for output files (default: reports)"
    )

    return parser.parse_args()


# ===============================================
# MAIN
# ===============================================

def main():
    args = parse_args()

    # Get domain from arg or prompt
    domain = args.domain
    if not domain:
        try:
            domain = input("Enter target domain: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n[!] Aborted")
            sys.exit(0)

    if not domain:
        logger.error("No domain provided. Exiting.")
        sys.exit(1)

    # Normalize
    domain = (
        domain
        .replace("https://", "")
        .replace("http://", "")
        .split("/")[0]
        .strip()
    )

    print(f"\n{'=' * 60}")
    print(f"  AI Bug Bounty Recon")
    print(f"  Target : {domain}")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'=' * 60}\n")

    # ── Run scan ──────────────────────────────────
    start_time = time.time()

    try:
        results = run_recon(domain)
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        sys.exit(1)

    elapsed = time.time() - start_time
    logger.success(f"Scan completed in {elapsed:.1f}s")

    # ── Print summary ─────────────────────────────
    print_summary(results)

    # ── Verbose output ────────────────────────────
    if args.verbose:
        print_section(
            "Subdomains",
            results.get("subdomains", [])
        )

        print_section(
            "Alive Hosts",
            results.get("live_hosts", []),
            formatter=lambda h: f"[{h.get('status')}] {h.get('url')} {h.get('title', '')}"
        )

        print_section(
            "Endpoints",
            results.get("endpoints", []),
            formatter=lambda e: f"[{', '.join(e.get('tags', []))}] {e.get('url')}"
                                if isinstance(e, dict) else str(e)
        )

        print_section(
            "Technologies",
            [f"{url}: {', '.join(techs)}"
             for url, techs in results.get("technologies", {}).items()]
        )

        print_section(
            "JS Intelligence",
            results.get("js_intelligence", []),
            formatter=lambda j: f"[{j.get('severity')}] [{j.get('type')}] {j.get('value', '')[:80]}"
        )

        print_section(
            "Directories",
            results.get("directories", []),
            formatter=lambda d: f"[{d.get('severity')}] [{d.get('status')}] {d.get('url')}"
        )

        print_section(
            "Findings",
            results.get("findings", []),
            formatter=lambda f: (
                f"[{f.get('severity')}] [{f.get('type')}] "
                f"cvss={f.get('cvss', 'N/A')} conf={f.get('confidence', 'N/A')}% "
                f"| {f.get('url', '')}"
            ) if isinstance(f, dict) else str(f),
            limit=50
        )

        print_section(
            "Attack Chains",
            results.get("attack_surface", {}).get("chains", []),
            formatter=lambda c: (
                f"[score={c.get('chain_score', 0)}] "
                f"{' → '.join(c.get('chain', []))}"
            ) if isinstance(c, dict) else str(c)
        )

    else:
        # Non-verbose: just print findings
        findings = results.get("findings", [])
        if findings:
            print_section(
                "Findings",
                findings,
                formatter=lambda f: (
                    f"[{f.get('severity', 'N/A')}] [{f.get('type', 'Unknown')}] "
                    f"| {f.get('url', '')}"
                ) if isinstance(f, dict) else str(f),
                limit=30
            )
        else:
            print("\n  No findings detected")

    # ── Payload suggestions ───────────────────────
    findings = results.get("findings", [])

    if not args.no_payloads and findings:
        print(f"\n{'─' * 50}")
        print("  PAYLOAD SUGGESTIONS")
        print(f"{'─' * 50}")
        try:
            for finding in findings[:20]:  # Cap at 20 to avoid spam
                exploit = generate_exploit(finding)
                if exploit:
                    print(f"  [{finding.get('type', 'Unknown')}] {finding.get('url', '')}")
                    print(f"    PoC: {exploit.get('poc', exploit.get('curl_command', ''))}")
        except Exception as e:
            logger.error(f"Payload suggestions failed: {e}")

    # ── Report generation ─────────────────────────
    if not args.no_report:
        print(f"\n{'─' * 50}")
        print("  GENERATING REPORT")
        print(f"{'─' * 50}")
        try:
            generate_report(
                domain,
                results.get("live_hosts", []),
                results.get("endpoints", []),
                findings,
                results.get("risk", {})
            )
            logger.success("Report generated successfully")
        except Exception as e:
            logger.error(f"Report generation failed: {e}")

    # ── Final timing ──────────────────────────────
    print(f"\n{'=' * 60}")
    print(f"  Finished: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Duration: {elapsed:.1f}s")
    print(f"{'=' * 60}\n")


if __name__ == "__main__":
    main()