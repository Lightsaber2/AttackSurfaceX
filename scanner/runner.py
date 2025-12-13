"""
runner.py

Executes Nmap scans in a controlled, auditable manner.
"""

from __future__ import annotations

import subprocess
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

from scanner.profiles import SCAN_PROFILES


class NmapNotInstalledError(Exception):
    pass


class ScanExecutionError(Exception):
    pass


class NmapRunner:
    def __init__(self, output_dir: str = "scans", timeout: int = 300) -> None:
        self.output_dir = Path(output_dir)
        self.timeout = timeout
        self._ensure_output_directory()
        self._verify_nmap_installation()

    def _ensure_output_directory(self) -> None:
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _verify_nmap_installation(self) -> None:
        if shutil.which("nmap") is None:
            raise NmapNotInstalledError("Nmap executable not found in PATH.")

    def run_scan(
        self,
        target: str,
        profile: str,
        dry_run: bool = False,
    ) -> Dict[str, str]:
        if profile not in SCAN_PROFILES:
            raise ValueError(f"Unknown scan profile: {profile}")

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        output_file = self.output_dir / f"scan_{timestamp}.xml"

        flags: List[str] = SCAN_PROFILES[profile]["flags"]

        command: List[str] = [
            "nmap",
            *flags,
            "-oX",
            str(output_file),
            target,
        ]

        if dry_run:
            return {
                "target": target,
                "profile": profile,
                "command": " ".join(command),
                "output_file": str(output_file),
                "timestamp": timestamp,
                "dry_run": True,
            }

        try:
            subprocess.run(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                timeout=self.timeout,
                check=True,
                text=True,
            )
        except subprocess.TimeoutExpired:
            raise ScanExecutionError("Nmap scan timed out.")
        except subprocess.CalledProcessError as exc:
            raise ScanExecutionError(
                f"Nmap scan failed: {exc.stderr.strip()}"
            ) from exc

        return {
            "target": target,
            "profile": profile,
            "command": " ".join(command),
            "output_file": str(output_file),
            "timestamp": timestamp,
            "dry_run": False,
        }
