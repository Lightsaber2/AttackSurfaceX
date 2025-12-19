"""
main.py

Enhanced orchestrator with CLI arguments, better error handling, and comprehensive logging.
"""

import argparse
import json
import sys
from pathlib import Path
from datetime import datetime, timezone

from tabulate import tabulate

from scanner.runner import NmapRunner, ScanResult
from parser.xml_parser import NmapXMLParser, ParseError
from logger.storage import StorageEngine
from analyzer.diff import ChangeDetector
from analyzer.risk import RiskScorer
from parser.events import PortStateEvent
from utils import app_logger, config


def setup_argument_parser() -> argparse.ArgumentParser:
    """Configure command-line argument parser."""
    parser = argparse.ArgumentParser(
        description="AttackSurfaceX - Network Attack Surface Monitoring Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                                    # Scan default target with default profile
  %(prog)s -t 192.168.1.1                     # Scan specific target
  %(prog)s -t scanme.nmap.org -p full         # Full port scan
  %(prog)s -t 10.0.0.0/24 -p stealth --dry-run  # Preview stealth scan command
  %(prog)s --list-profiles                    # Show available scan profiles
        """
    )
    
    parser.add_argument(
        "-t", "--target",
        type=str,
        default=config.get("scan.default_target", "scanme.nmap.org"),
        help="Target IP address, hostname, or CIDR range to scan"
    )
    
    parser.add_argument(
        "-p", "--profile",
        type=str,
        default=config.get("scan.default_profile", "fast"),
        choices=["fast", "full", "comprehensive", "stealth"],
        help="Scan profile to use (default: fast)"
    )
    
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show scan command without executing"
    )
    
    parser.add_argument(
        "--list-profiles",
        action="store_true",
        help="List available scan profiles and exit"
    )
    
    parser.add_argument(
        "--no-report",
        action="store_true",
        help="Skip report generation (only save to database)"
    )
    
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )
    
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress non-essential output"
    )
    
    return parser


def print_header(title: str, quiet: bool = False) -> None:
    """Print a formatted section header."""
    if not quiet:
        print("\n" + "=" * 60)
        print(title)
        print("=" * 60)


def list_scan_profiles(runner: NmapRunner) -> None:
    """Display available scan profiles and exit."""
    profiles = runner.list_profiles()
    
    print("\nAvailable Scan Profiles:")
    print("=" * 60)
    
    for name, description in profiles.items():
        print(f"\n{name:12} - {description}")
    
    print("\n" + "=" * 60)


def handle_scan_result(scan_result: ScanResult, quiet: bool = False) -> bool:
    """
    Handle scan result, logging appropriately.
    
    Returns:
        True if scan succeeded, False otherwise
    """
    if scan_result.dry_run:
        print_header("Dry Run Mode", quiet)
        print(f"Command: {scan_result.command}")
        print(f"\nOutput would be saved to: {scan_result.output_file}")
        return True
    
    if not scan_result.success:
        app_logger.error(f"Scan failed: {scan_result.error_message}")
        if not quiet:
            print(f"\n[!] Scan Failed: {scan_result.error_message}")
        return False
    
    if not quiet:
        print(f"[+] Scan completed in {scan_result.duration:.2f}s")
    
    return True


def main() -> int:
    """
    Main execution function.
    
    Returns:
        Exit code (0 for success, 1 for failure)
    """
    # Parse command-line arguments
    parser = setup_argument_parser()
    args = parser.parse_args()
    
    # Handle --list-profiles
    if args.list_profiles:
        runner = NmapRunner()
        list_scan_profiles(runner)
        return 0
    
    # Configure logging based on verbosity
    if args.verbose:
        app_logger.setLevel("DEBUG")
    elif args.quiet:
        app_logger.setLevel("WARNING")
    
    quiet = args.quiet
    
    try:
        # --------------------------------------------------
        # Initialize components
        # --------------------------------------------------
        app_logger.info("=== AttackSurfaceX Started ===")
        app_logger.info(f"Target: {args.target}, Profile: {args.profile}")
        
        runner = NmapRunner()
        parser_obj = NmapXMLParser()
        storage = StorageEngine()
        
        # --------------------------------------------------
        # Execute scan
        # --------------------------------------------------
        print_header("Attack Surface Scan Started", quiet)
        
        scan_result = runner.run_scan(
            target=args.target,
            profile=args.profile,
            dry_run=args.dry_run,
        )
        
        # Handle scan result
        if not handle_scan_result(scan_result, quiet):
            return 1
        
        # Exit if dry run
        if scan_result.dry_run:
            return 0
        
        # --------------------------------------------------
        # Parse XML output
        # --------------------------------------------------
        app_logger.info("Parsing scan results...")
        
        try:
            events = parser_obj.parse(scan_result.output_file)
        except (FileNotFoundError, ParseError) as e:
            app_logger.error(f"Failed to parse scan results: {e}")
            if not quiet:
                print(f"\n[!] Parse Error: {e}")
            return 1
        
        # --------------------------------------------------
        # Store results in database
        # --------------------------------------------------
        app_logger.info("Storing scan results...")
        
        try:
            scan_id = storage.create_scan(
                target=args.target,
                profile=args.profile,
                duration=scan_result.duration
            )
            storage.store_events(scan_id, events)
        except Exception as e:
            app_logger.error(f"Failed to store scan results: {e}")
            if not quiet:
                print(f"\n[!] Storage Error: {e}")
            return 1
        
        if not quiet:
            print(f"[+] Scan ID       : {scan_id}")
            print(f"[+] Target        : {args.target}")
            print(f"[+] Profile       : {args.profile}")
            print(f"[+] Events Parsed : {len(events)}")
        
        # --------------------------------------------------
        # Change detection
        # --------------------------------------------------
        changes = {"opened_ports": [], "closed_ports": []}
        
        try:
            last_scan = storage.get_last_scan(args.target)
            
            if last_scan and last_scan["id"] != scan_id:
                detector = ChangeDetector()
                diff = detector.detect_changes(last_scan["id"], scan_id)
                changes = {
                    "opened_ports": list(diff["opened_ports"]),
                    "closed_ports": list(diff["closed_ports"]),
                }
        except Exception as e:
            app_logger.warning(f"Change detection failed: {e}")
        
        print_header("Attack Surface Changes", quiet)
        
        if not changes["opened_ports"] and not changes["closed_ports"]:
            if not quiet:
                print("No changes detected since last scan.")
        else:
            if changes["opened_ports"] and not quiet:
                print("Newly Opened Ports:")
                for host, port in changes["opened_ports"]:
                    print(f"  [+] {host}:{port}")
            
            if changes["closed_ports"] and not quiet:
                print("Recently Closed Ports:")
                for host, port in changes["closed_ports"]:
                    print(f"  [-] {host}:{port}")
        
        # --------------------------------------------------
        # Risk scoring
        # --------------------------------------------------
        scorer = RiskScorer()
        port_events = [e for e in events if isinstance(e, PortStateEvent)]
        risks = scorer.score_events(port_events)
        
        print_header("Risk Assessment", quiet)
        
        if not risks:
            if not quiet:
                print("No risky services detected.")
        elif not quiet:
            # Sort by risk score (highest first)
            risks.sort(key=lambda x: x["risk"], reverse=True)
            
            table = [
                [r["host"], r["port"], r["service"], f'{r["risk"]}/10']
                for r in risks
            ]
            print(
                tabulate(
                    table,
                    headers=["Host", "Port", "Service", "Risk"],
                    tablefmt="grid",
                )
            )
        
        # --------------------------------------------------
        # Generate report (if not disabled)
        # --------------------------------------------------
        if not args.no_report:
            report = {
                "scan_id": scan_id,
                "target": args.target,
                "profile": args.profile,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "duration_seconds": scan_result.duration,
                "summary": {
                    "total_events": len(events),
                    "open_ports": len([e for e in port_events if e.state == "open"]),
                    "closed_ports": len([e for e in port_events if e.state == "closed"]),
                    "filtered_ports": len([e for e in port_events if e.state == "filtered"]),
                    "high_risk_findings": len([r for r in risks if r["risk"] >= 8]),
                    "medium_risk_findings": len([r for r in risks if 5 <= r["risk"] < 8]),
                },
                "changes": changes,
                "risk_assessment": risks,
            }
            
            # Save report
            reports_dir = Path(config.get("paths.reports_dir", "reports"))
            reports_dir.mkdir(exist_ok=True)
            
            report_path = reports_dir / f"report_scan_{scan_id}.json"
            
            try:
                with open(report_path, "w", encoding="utf-8") as f:
                    json.dump(report, f, indent=4)
                
                print_header("Report Generated", quiet)
                if not quiet:
                    print(f"Saved to: {report_path}")
                
                app_logger.info(f"Report saved: {report_path}")
            except Exception as e:
                app_logger.error(f"Failed to save report: {e}")
                if not quiet:
                    print(f"[!] Failed to save report: {e}")
        
        app_logger.info("=== AttackSurfaceX Completed Successfully ===")
        return 0
    
    except KeyboardInterrupt:
        app_logger.warning("Scan interrupted by user")
        if not quiet:
            print("\n\n[!] Scan interrupted by user")
        return 130  # Standard exit code for SIGINT
    
    except Exception as e:
        app_logger.error(f"Unexpected error: {e}", exc_info=True)
        if not quiet:
            print(f"\n[!] Error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())