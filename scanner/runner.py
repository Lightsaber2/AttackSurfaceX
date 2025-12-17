"""
runner.py

Enhanced Nmap scan execution with better error handling and logging.
"""

from __future__ import annotations

import subprocess
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass

from scanner.profiles import SCAN_PROFILES
from utils import app_logger, config


class NmapNotInstalledError(Exception):
    """Raised when Nmap is not found in system PATH."""
    pass


class ScanExecutionError(Exception):
    """Raised when scan execution fails."""
    pass


@dataclass
class ScanResult:
    """Structured scan result with all relevant information."""
    target: str
    profile: str
    command: str
    output_file: str
    timestamp: str
    success: bool
    duration: float
    error_message: Optional[str] = None
    dry_run: bool = False


class NmapRunner:
    """
    Executes Nmap scans in a controlled, auditable manner with comprehensive error handling.
    """
    
    def __init__(self, output_dir: Optional[str] = None, timeout: Optional[int] = None) -> None:
        self.output_dir = Path(output_dir or config.get("paths.scans_dir", "scans"))
        self.timeout = timeout or config.get("scan.timeout", 300)
        self.logger = app_logger
        
        self._ensure_output_directory()
        self._verify_nmap_installation()

    def _ensure_output_directory(self) -> None:
        """Create output directory if it doesn't exist."""
        try:
            self.output_dir.mkdir(parents=True, exist_ok=True)
            self.logger.debug(f"Output directory ready: {self.output_dir}")
        except Exception as e:
            self.logger.error(f"Failed to create output directory: {e}")
            raise

    def _verify_nmap_installation(self) -> None:
        """Verify that Nmap is installed and accessible."""
        if shutil.which("nmap") is None:
            self.logger.error("Nmap executable not found in system PATH")
            raise NmapNotInstalledError(
                "Nmap is not installed or not in PATH. "
                "Please install from https://nmap.org/download.html"
            )
        
        self.logger.info("Nmap installation verified")

    def run_scan(
        self,
        target: str,
        profile: str,
        dry_run: bool = False,
    ) -> ScanResult:
        """
        Execute an Nmap scan with the specified profile.
        
        Args:
            target: IP address, hostname, or CIDR range to scan
            profile: Scan profile name (fast, full, stealth)
            dry_run: If True, only show command without executing
        
        Returns:
            ScanResult object with scan details and status
        
        Raises:
            ValueError: If profile is invalid
            ScanExecutionError: If scan execution fails
        """
        if profile not in SCAN_PROFILES:
            available = ", ".join(SCAN_PROFILES.keys())
            error_msg = f"Unknown scan profile '{profile}'. Available: {available}"
            self.logger.error(error_msg)
            raise ValueError(error_msg)

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

        command_str = " ".join(command)
        self.logger.info(f"Preparing scan: target={target}, profile={profile}")
        self.logger.debug(f"Command: {command_str}")

        # Dry run mode - just show what would be executed
        if dry_run:
            self.logger.info("Dry run mode - scan not executed")
            return ScanResult(
                target=target,
                profile=profile,
                command=command_str,
                output_file=str(output_file),
                timestamp=timestamp,
                success=True,
                duration=0.0,
                dry_run=True,
            )

        # Execute the actual scan
        start_time = time.time()
        
        try:
            self.logger.info(f"Starting Nmap scan of {target}...")
            
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=self.timeout,
                check=True,
                text=True,
            )
            
            duration = time.time() - start_time
            
            # Verify output file was created
            if not output_file.exists():
                raise ScanExecutionError("Scan completed but output file was not created")
            
            self.logger.info(
                f"Scan completed successfully in {duration:.2f}s: {output_file.name}"
            )
            
            return ScanResult(
                target=target,
                profile=profile,
                command=command_str,
                output_file=str(output_file),
                timestamp=timestamp,
                success=True,
                duration=duration,
            )
        
        except subprocess.TimeoutExpired:
            duration = time.time() - start_time
            error_msg = f"Scan timed out after {self.timeout} seconds"
            self.logger.error(error_msg)
            
            return ScanResult(
                target=target,
                profile=profile,
                command=command_str,
                output_file=str(output_file),
                timestamp=timestamp,
                success=False,
                duration=duration,
                error_message=error_msg,
            )
        
        except subprocess.CalledProcessError as exc:
            duration = time.time() - start_time
            error_msg = f"Nmap scan failed: {exc.stderr.strip() or 'Unknown error'}"
            self.logger.error(error_msg)
            
            return ScanResult(
                target=target,
                profile=profile,
                command=command_str,
                output_file=str(output_file),
                timestamp=timestamp,
                success=False,
                duration=duration,
                error_message=error_msg,
            )
        
        except Exception as e:
            duration = time.time() - start_time
            error_msg = f"Unexpected error during scan: {str(e)}"
            self.logger.error(error_msg, exc_info=True)
            
            return ScanResult(
                target=target,
                profile=profile,
                command=command_str,
                output_file=str(output_file),
                timestamp=timestamp,
                success=False,
                duration=duration,
                error_message=error_msg,
            )

    def list_profiles(self) -> Dict[str, str]:
        """Return available scan profiles with descriptions."""
        return {
            name: details["description"]
            for name, details in SCAN_PROFILES.items()
        }