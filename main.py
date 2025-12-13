import json
from pathlib import Path
from datetime import datetime, timezone

from tabulate import tabulate

from scanner.runner import NmapRunner
from parser.xml_parser import NmapXMLParser
from logger.storage import StorageEngine
from analyzer.diff import ChangeDetector
from analyzer.risk import RiskScorer
from parser.events import PortStateEvent


def print_header(title: str) -> None:
    """Print a formatted section header."""
    print("\n" + "=" * 60)
    print(title)
    print("=" * 60)


def main() -> None:
    # --------------------------------------------------
    # Central configuration (easy to extend later)
    # --------------------------------------------------
    config = {
        "target": "scanme.nmap.org",
        "profile": "fast",
        "dry_run": False,   # Set True to see command without executing
    }

    # --------------------------------------------------
    # Run scan
    # --------------------------------------------------
    print_header("Attack Surface Scan Started")

    runner = NmapRunner()
    scan_result = runner.run_scan(
        target=config["target"],
        profile=config["profile"],
        dry_run=config["dry_run"],
    )

    # Handle dry-run mode
    if scan_result.get("dry_run"):
        print("[*] Dry run enabled")
        print(f"Command: {scan_result['command']}")
        return

    # --------------------------------------------------
    # Parse XML output
    # --------------------------------------------------
    parser = NmapXMLParser()
    events = parser.parse(scan_result["output_file"])

    # --------------------------------------------------
    # Store results
    # --------------------------------------------------
    storage = StorageEngine()
    scan_id = storage.create_scan(config["target"], config["profile"])
    storage.store_events(scan_id, events)

    print(f"[+] Scan ID       : {scan_id}")
    print(f"[+] Target        : {config['target']}")
    print(f"[+] Profile       : {config['profile']}")
    print(f"[+] Events Parsed : {len(events)}")

    # --------------------------------------------------
    # Change detection
    # --------------------------------------------------
    changes = {"opened_ports": [], "closed_ports": []}

    if scan_id > 1:
        detector = ChangeDetector()
        diff = detector.detect_changes(scan_id - 1, scan_id)
        changes = {
            "opened_ports": list(diff["opened_ports"]),
            "closed_ports": list(diff["closed_ports"]),
        }

    print_header("Attack Surface Changes")

    if not changes["opened_ports"] and not changes["closed_ports"]:
        print("No changes detected since last scan.")
    else:
        if changes["opened_ports"]:
            print("Newly Opened Ports:")
            for host, port in changes["opened_ports"]:
                print(f"  [+] {host}:{port}")

        if changes["closed_ports"]:
            print("Recently Closed Ports:")
            for host, port in changes["closed_ports"]:
                print(f"  [-] {host}:{port}")

    # --------------------------------------------------
    # Risk scoring
    # --------------------------------------------------
    scorer = RiskScorer()
    port_events = [e for e in events if isinstance(e, PortStateEvent)]
    risks = scorer.score_events(port_events)

    print_header("Risk Assessment")

    if not risks:
        print("No risky services detected.")
    else:
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
    # Build JSON report
    # --------------------------------------------------
    report = {
        "scan_id": scan_id,
        "target": config["target"],
        "profile": config["profile"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_events": len(events),
            "open_ports": len([e for e in port_events if e.state == "open"]),
            "high_risk_findings": len([r for r in risks if r["risk"] >= 8]),
        },
        "changes": changes,
        "risk_assessment": risks,
    }

    # --------------------------------------------------
    # Save report
    # --------------------------------------------------
    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)

    report_path = reports_dir / f"report_scan_{scan_id}.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4)

    print_header("Report Generated")
    print(f"Saved to: {report_path}")


if __name__ == "__main__":
    main()
