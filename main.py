"""
main.py

Enhanced orchestrator with PDF reports, progress bars, colors, and improved risk scoring.
"""

import argparse
import json
import sys
from pathlib import Path
from datetime import datetime, timezone

from tabulate import tabulate
from colorama import Fore, Style

from scanner.runner import NmapRunner, ScanResult
from parser.xml_parser import NmapXMLParser, ParseError
from logger.storage import StorageEngine
from analyzer.diff import ChangeDetector
from analyzer.risk import RiskScorer
from parser.events import PortStateEvent
from report_generators import PDFReportGenerator
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
  %(prog)s --rate-limit 100                   # Limit to 100 packets/sec
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
        "--no-pdf",
        action="store_true",
        help="Skip PDF report generation (only JSON)"
    )
    
    parser.add_argument(
        "--rate-limit",
        type=int,
        default=config.get("scan.rate_limit"),
        help="Limit scan rate (packets per second)"
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
    """Print a formatted section header with color."""
    if not quiet:
        print(f"\n{Fore.CYAN}{'=' * 60}")
        print(f"{title}")
        print(f"{'=' * 60}{Style.RESET_ALL}")


def list_scan_profiles(runner: NmapRunner) -> None:
    """Display available scan profiles and exit."""
    profiles = runner.list_profiles()
    
    print(f"\n{Fore.CYAN}Available Scan Profiles:")
    print("=" * 60)
    
    for name, description in profiles.items():
        print(f"\n{Fore.YELLOW}{name:15}{Style.RESET_ALL} - {description}")
    
    print(f"\n{'=' * 60}{Style.RESET_ALL}")


def handle_scan_result(scan_result: ScanResult, quiet: bool = False) -> bool:
    """Handle scan result, logging appropriately."""
    if scan_result.dry_run:
        return True
    
    if not scan_result.success:
        app_logger.error(f"Scan failed: {scan_result.error_message}")
        if not quiet:
            print(f"\n{Fore.RED}[!] Scan Failed:{Style.RESET_ALL} {scan_result.error_message}")
        return False
    
    return True


def main() -> int:
    """Main execution function."""
    parser = setup_argument_parser()
    args = parser.parse_args()
    
    # Handle --list-profiles
    if args.list_profiles:
        runner = NmapRunner()
        list_scan_profiles(runner)
        return 0
    
    # Configure logging
    if args.verbose:
        app_logger.setLevel("DEBUG")
    elif args.quiet:
        app_logger.setLevel("WARNING")
    
    quiet = args.quiet
    
    try:
        # Initialize components
        app_logger.info("=== AttackSurfaceX Started ===")
        app_logger.info(f"Target: {args.target}, Profile: {args.profile}")
        
        runner = NmapRunner(rate_limit=args.rate_limit)
        parser_obj = NmapXMLParser()
        storage = StorageEngine()
        
        # Execute scan
        print_header("Attack Surface Scan Started", quiet)
        
        scan_result = runner.run_scan(
            target=args.target,
            profile=args.profile,
            dry_run=args.dry_run,
        )
        
        if not handle_scan_result(scan_result, quiet):
            return 1
        
        if scan_result.dry_run:
            return 0
        
        # Parse XML output
        app_logger.info("Parsing scan results...")
        
        try:
            events = parser_obj.parse(scan_result.output_file)
        except (FileNotFoundError, ParseError) as e:
            app_logger.error(f"Failed to parse scan results: {e}")
            if not quiet:
                print(f"\n{Fore.RED}[!] Parse Error:{Style.RESET_ALL} {e}")
            return 1
        
        # Store results
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
                print(f"\n{Fore.RED}[!] Storage Error:{Style.RESET_ALL} {e}")
            return 1
        
        if not quiet:
            print(f"\n{Fore.GREEN}[+]{Style.RESET_ALL} Scan ID       : {Fore.YELLOW}{scan_id}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Target        : {args.target}")
            print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Profile       : {args.profile}")
            print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Events Parsed : {len(events)}")
        
        # Change detection
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
                print(f"{Fore.GREEN}Newly Opened Ports:{Style.RESET_ALL}")
                for host, port in changes["opened_ports"]:
                    print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} {host}:{port}")
            
            if changes["closed_ports"] and not quiet:
                print(f"\n{Fore.YELLOW}Recently Closed Ports:{Style.RESET_ALL}")
                for host, port in changes["closed_ports"]:
                    print(f"  {Fore.YELLOW}[-]{Style.RESET_ALL} {host}:{port}")
        
        # Enhanced risk scoring with context
        scorer = RiskScorer()
        port_events = [e for e in events if isinstance(e, PortStateEvent)]
        
        # Get port histories for context
        port_histories = {}
        for event in port_events:
            history = storage.get_port_history(event.host, event.port, event.protocol)
            if history:
                key = (event.host, event.port, event.protocol)
                port_histories[key] = history
        
        # Score with context
        risks = scorer.score_events(port_events, port_histories)
        
        print_header("Risk Assessment", quiet)
        
        if not risks:
            if not quiet:
                print("No risky services detected.")
        elif not quiet:
            # Color code by risk level
            table_data = []
            for r in risks:
                risk_val = r["risk"]
                if risk_val >= 8:
                    risk_str = f"{Fore.RED}{risk_val}/10{Style.RESET_ALL}"
                elif risk_val >= 5:
                    risk_str = f"{Fore.YELLOW}{risk_val}/10{Style.RESET_ALL}"
                else:
                    risk_str = f"{Fore.GREEN}{risk_val}/10{Style.RESET_ALL}"
                
                table_data.append([
                    r["host"],
                    r["port"],
                    r["service"],
                    risk_str
                ])
            
            print(tabulate(
                table_data,
                headers=["Host", "Port", "Service", "Risk"],
                tablefmt="grid",
            ))
            
            # Show risk factors for high-risk items
            high_risks = [r for r in risks if r["risk"] >= 8]
            if high_risks:
                print(f"\n{Fore.RED}High Risk Details:{Style.RESET_ALL}")
                for r in high_risks[:3]:  # Show top 3
                    print(f"\n  {Fore.YELLOW}Port {r['port']} ({r['service']}):{Style.RESET_ALL}")
                    for factor in r.get('risk_factors', []):
                        print(f"    • {factor}")
        
        # Generate reports
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
            
            reports_dir = Path(config.get("paths.reports_dir", "reports"))
            reports_dir.mkdir(exist_ok=True)
            
            # JSON report
            json_path = reports_dir / f"report_scan_{scan_id}.json"
            try:
                with open(json_path, "w", encoding="utf-8") as f:
                    json.dump(report, f, indent=4)
                
                print_header("Reports Generated", quiet)
                if not quiet:
                    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} JSON: {json_path}")
                
                app_logger.info(f"JSON report saved: {json_path}")
            except Exception as e:
                app_logger.error(f"Failed to save JSON report: {e}")
            
            # PDF report (if enabled)
            if config.get("reports.generate_pdf") and not args.no_pdf:
                pdf_path = reports_dir / f"report_scan_{scan_id}.pdf"
                try:
                    pdf_gen = PDFReportGenerator()
                    if pdf_gen.generate(report, str(pdf_path)):
                        if not quiet:
                            print(f"{Fore.GREEN}[+]{Style.RESET_ALL} PDF:  {pdf_path}")
                    else:
                        if not quiet:
                            print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} PDF generation failed (see logs)")
                except Exception as e:
                    app_logger.error(f"PDF generation error: {e}")
                    if not quiet:
                        print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} PDF generation failed: {e}")
        
        app_logger.info("=== AttackSurfaceX Completed Successfully ===")
        
        if not quiet:
            print(f"\n{Fore.GREEN}✓ Scan complete!{Style.RESET_ALL}\n")
        
        return 0
    
    except KeyboardInterrupt:
        app_logger.warning("Scan interrupted by user")
        if not quiet:
            print(f"\n\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
        return 130
    
    except Exception as e:
        app_logger.error(f"Unexpected error: {e}", exc_info=True)
        if not quiet:
            print(f"\n{Fore.RED}[!] Error:{Style.RESET_ALL} {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())