"""
runner.py

Responsible for executing Nmap scans in a controlled and auditable manner.
This module acts as the execution engine for all scan operations.
"""

from __future__ import annotations

import subprocess
import shutil
from datetime import datetime
from pathlib import Path
from typing import List, Dict

from scanner.profiles import SCAN_PROFILES


class NmapNotInstalledError(Exception):
    """Raised when Nmap is not available in system PATH."""
    pass


class ScanExecutionError(Exception):
    """Raised when an Nmap scan fails to execute properly."""
    pass


class NmapRunner:
    """
    Encapsulates all logic required to execute Nmap scans.

    This class is intentionally isolated from parsing and analysis logic
    to maintain clean separation of concerns.
    """

    def __init__(self, output_dir: str = "scans") -> None:
        """
        Initialize the Nmap runner.

        Args:
            output_dir (str): Directory where Nmap XML outputs will be stored.
        """
        self.output_dir = Path(output_dir)
        self._ensure_output_directory()
        self._verify_nmap_installation()

    def _ensure_output_directory(self) -> None:
        """Ensure the scan output directory exists."""
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _verify_nmap_installation(self) -> None:
        """
        Verify that Nmap is available in system PATH.

        Raises:
            NmapNotInstalledError: If Nmap binary is not found.
        """
        if shutil.which("nmap") is None:
            raise NmapNotInstalledError(
                "Nmap executable not found in PATH. Please install Nmap."
            )

    def run_scan(self, target: str, profile: str) -> Dict[str, str]:
        """
        Execute an Nmap scan using a predefined scan profile.

        Args:
            target (str): Target IP address, hostname, or CIDR range.
            profile (str): Name of the scan profile to use.

        Returns:
            Dict[str, str]: Metadata about the executed scan.

        Raises:
            ValueError: If an invalid scan profile is supplied.
            ScanExecutionError: If the scan execution fails.
        """
        if profile not in SCAN_PROFILES:
            raise ValueError(f"Unknown scan profile: {profile}")

        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        output_file = self.output_dir / f"scan_{timestamp}.xml"

        command: List[str] = [
            "nmap",
            *SCAN_PROFILES[profile],
            "-oX",
            str(output_file),
            target,
        ]

        try:
            subprocess.run(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                check=True,
                text=True,
            )
        except subprocess.CalledProcessError as exc:
            raise ScanExecutionError(
                f"Nmap scan failed: {exc.stderr.strip()}"
            ) from exc

        return {
            "target": target,
            "profile": profile,
            "output_file": str(output_file),
            "timestamp": timestamp,
        }
