"""
runner.py

Enhanced Nmap scan execution with progress bars, rate limiting, and better UX.
"""

from __future__ import annotations

import subprocess
import shutil
import time
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass

from tqdm import tqdm
from colorama import Fore, Style, init as colorama_init

from scanner.profiles import SCAN_PROFILES
from utils import app_logger, config

# Initialize colorama for Windows compatibility
colorama_init(autoreset=True)


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
    Executes Nmap scans with progress indication, rate limiting, and colorized output.
    """
    
    def __init__(
        self, 
        output_dir: Optional[str] = None, 
        timeout: Optional[int] = None,
        rate_limit: Optional[int] = None,
        show_progress: bool = True
    ) -> None:
        self.output_dir = Path(output_dir or config.get("paths.scans_dir", "scans"))
        self.timeout = timeout or config.get("scan.timeout", 300)
        self.rate_limit = rate_limit or config.get("scan.rate_limit", None)
        self.show_progress = show_progress
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
        
        self.logger.info(f"{Fore.GREEN}✓{Style.RESET_ALL} Nmap installation verified")

    def _apply_rate_limiting(self, flags: List[str]) -> List[str]:
        """Apply rate limiting to Nmap flags if configured."""
        if self.rate_limit:
            # Add rate limiting flag
            # --max-rate limits packets per second
            flags.append("--max-rate")
            flags.append(str(self.rate_limit))
            
            self.logger.info(f"Rate limiting applied: {self.rate_limit} packets/sec")
        
        return flags

    def _show_progress(self, duration: int, profile: str) -> None:
        """Show a progress bar during scan execution."""
        desc = f"{Fore.CYAN}Scanning ({profile}){Style.RESET_ALL}"
        
        with tqdm(
            total=duration,
            desc=desc,
            unit="s",
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}s [{elapsed}]",
            colour="cyan"
        ) as pbar:
            start = time.time()
            while time.time() - start < duration:
                time.sleep(1)
                pbar.update(1)

    def run_scan(
        self,
        target: str,
        profile: str,
        dry_run: bool = False,
    ) -> ScanResult:
        """
        Execute an Nmap scan with progress indication and rate limiting.
        
        Args:
            target: IP address, hostname, or CIDR range to scan
            profile: Scan profile name (fast, full, comprehensive, stealth)
            dry_run: If True, only show command without executing
        
        Returns:
            ScanResult object with scan details and status
        """
        if profile not in SCAN_PROFILES:
            available = ", ".join(SCAN_PROFILES.keys())
            error_msg = f"Unknown scan profile '{profile}'. Available: {available}"
            self.logger.error(f"{Fore.RED}✗{Style.RESET_ALL} {error_msg}")
            raise ValueError(error_msg)

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        output_file = self.output_dir / f"scan_{timestamp}.xml"
        
        # Get flags and apply rate limiting
        flags: List[str] = SCAN_PROFILES[profile]["flags"].copy()
        flags = self._apply_rate_limiting(flags)

        command: List[str] = [
            "nmap",
            *flags,
            "-oX",
            str(output_file),
            target,
        ]

        command_str = " ".join(command)
        
        print(f"\n{Fore.CYAN}[i]{Style.RESET_ALL} Target: {Fore.YELLOW}{target}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[i]{Style.RESET_ALL} Profile: {Fore.YELLOW}{profile}{Style.RESET_ALL}")
        
        self.logger.info(f"Preparing scan: target={target}, profile={profile}")
        self.logger.debug(f"Command: {command_str}")

        # Dry run mode
        if dry_run:
            print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Dry run mode - scan not executed")
            print(f"{Fore.CYAN}Command:{Style.RESET_ALL} {command_str}")
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

        # Execute the scan
        start_time = time.time()
        
        # Start progress indicator in separate thread if enabled
        progress_thread = None
        if self.show_progress and not dry_run:
            progress_thread = threading.Thread(
                target=self._show_progress, 
                args=(self.timeout, profile),
                daemon=True
            )
            progress_thread.start()
        
        try:
            print(f"\n{Fore.CYAN}[→]{Style.RESET_ALL} Starting Nmap scan...")
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
            
            print(f"\n{Fore.GREEN}✓{Style.RESET_ALL} Scan completed in {Fore.GREEN}{duration:.2f}s{Style.RESET_ALL}")
            self.logger.info(f"Scan completed successfully in {duration:.2f}s: {output_file.name}")
            
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
            print(f"\n{Fore.RED}✗{Style.RESET_ALL} {error_msg}")
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
            print(f"\n{Fore.RED}✗{Style.RESET_ALL} {error_msg}")
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
            print(f"\n{Fore.RED}✗{Style.RESET_ALL} {error_msg}")
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