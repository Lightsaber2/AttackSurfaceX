"""
risk.py

Enhanced risk scoring with historical context and anomaly detection.
"""

from typing import Dict, List, Optional
from datetime import datetime

from parser.events import PortStateEvent
from utils import app_logger


class RiskScorer:
    """
    Contextual risk scoring engine that considers service type,
    port characteristics, and historical behavior.
    """

    # Base risk scores by service name
    SERVICE_RISK: Dict[str, int] = {
        # Critical (9-10) - Unencrypted legacy protocols
        "telnet": 10,
        "ftp": 9,
        "tftp": 9,
        "rlogin": 10,
        "rsh": 10,
        "pptp": 9,
        
        # High (7-8) - Remote access with known vulnerabilities
        "rdp": 8,
        "vnc": 8,
        "smb": 8,
        "microsoft-ds": 8,
        "netbios-ssn": 7,
        
        # Medium-High (5-6) - Email protocols (often targeted)
        "smtp": 6,
        "pop3": 6,
        "imap": 5,
        
        # Medium (4-5) - Common services
        "ssh": 4,
        "mysql": 5,
        "postgresql": 5,
        "mssql": 5,
        "oracle": 5,
        
        # Low-Medium (3-4) - Web services
        "http": 3,
        "http-proxy": 3,
        "apache": 3,
        
        # Low (1-2) - Encrypted/modern protocols
        "https": 2,
        "ssh-tunnel": 2,
        "domain": 1,
    }
    
    # Port ranges with special significance
    PRIVILEGED_PORTS = range(1, 1024)
    EPHEMERAL_PORTS = range(49152, 65536)
    COMMON_BACKDOOR_PORTS = {31337, 12345, 54321, 1337, 6666, 6667}
    
    def __init__(self):
        self.logger = app_logger

    def score_event(
        self, 
        event: PortStateEvent,
        port_history: Optional[Dict] = None
    ) -> int:
        """
        Assign a contextual risk score to a port event.
        
        Args:
            event: The port state event to score
            port_history: Historical data for this port (from port_history table)
        
        Returns:
            Risk score from 0-10
        """
        if event.state != "open":
            return 0

        # Start with base service risk
        score = self.SERVICE_RISK.get(event.service, 2)
        
        # Apply contextual modifiers
        score = self._apply_port_modifiers(score, event.port)
        score = self._apply_history_modifiers(score, port_history)
        score = self._apply_version_modifiers(score, event)
        
        return min(score, 10)

    def _apply_port_modifiers(self, score: int, port: int) -> int:
        """Apply risk modifiers based on port number."""
        # Privileged ports (1-1023) - slight increase
        if port in self.PRIVILEGED_PORTS:
            score += 1
        
        # Known backdoor ports - major increase
        if port in self.COMMON_BACKDOOR_PORTS:
            score += 3
            self.logger.warning(f"Known backdoor port detected: {port}")
        
        # Ephemeral ports (49152-65535) - unusual for services
        if port in self.EPHEMERAL_PORTS:
            score += 2
            self.logger.warning(f"Service on ephemeral port: {port}")
        
        return score

    def _apply_history_modifiers(
        self, 
        score: int, 
        history: Optional[Dict]
    ) -> int:
        """Apply risk modifiers based on historical behavior."""
        if not history:
            # No history = first time seeing this port
            score += 2
            self.logger.info("New port detected (no history)")
            return score
        
        seen_count = history.get('seen_count', 0)
        
        # Very new ports (seen 1-2 times) are suspicious
        if seen_count <= 2:
            score += 3
            self.logger.warning(f"Suspicious: Port seen only {seen_count} time(s)")
        
        # Established ports (seen 10+ times) are less risky
        elif seen_count >= 10:
            score -= 1
            self.logger.debug(f"Established port (seen {seen_count} times)")
        
        # Check if port was recently closed and reopened
        if history.get('current_state') == 'closed':
            score += 2
            self.logger.warning("Port was previously closed, now reopened")
        
        return score

    def _apply_version_modifiers(
        self, 
        score: int, 
        event: PortStateEvent
    ) -> int:
        """Apply risk modifiers based on service version info."""
        # No version info = harder to patch/verify
        if not event.version:
            score += 1
        
        # Check for old/vulnerable versions (basic detection)
        if event.product:
            product_lower = event.product.lower()
            
            # Old SSH versions
            if 'openssh' in product_lower and event.version:
                try:
                    version_num = float(event.version.split('.')[0])
                    if version_num < 7.0:
                        score += 2
                        self.logger.warning(f"Old OpenSSH version: {event.version}")
                except (ValueError, IndexError):
                    pass
            
            # Old Apache versions
            if 'apache' in product_lower and event.version:
                if '2.2' in event.version or '2.0' in event.version:
                    score += 2
                    self.logger.warning(f"Old Apache version: {event.version}")
        
        return score

    def score_events(
        self, 
        events: List[PortStateEvent],
        port_histories: Optional[Dict[tuple, Dict]] = None
    ) -> List[Dict]:
        """
        Score all port events and return risk summaries.
        
        Args:
            events: List of port state events to score
            port_histories: Dict mapping (host, port, protocol) to history data
        
        Returns:
            List of risk assessment dictionaries
        """
        results = []
        port_histories = port_histories or {}

        for event in events:
            # Get history for this specific port
            history_key = (event.host, event.port, event.protocol)
            history = port_histories.get(history_key)
            
            # Calculate risk
            risk = self.score_event(event, history)

            if risk > 0:
                result = {
                    "host": event.host,
                    "port": event.port,
                    "service": event.service or "unknown",
                    "product": event.product,
                    "version": event.version,
                    "risk": risk,
                    "risk_factors": self._get_risk_factors(event, history, risk)
                }
                results.append(result)
        
        # Sort by risk (highest first)
        results.sort(key=lambda x: x["risk"], reverse=True)
        
        return results

    def _get_risk_factors(
        self, 
        event: PortStateEvent, 
        history: Optional[Dict],
        risk_score: int
    ) -> List[str]:
        """
        Generate human-readable list of risk factors.
        
        Returns:
            List of strings explaining why this is risky
        """
        factors = []
        
        # Service-based factors
        if event.service in ["telnet", "ftp", "rlogin", "rsh"]:
            factors.append("Unencrypted legacy protocol")
        elif event.service in ["rdp", "smb", "vnc"]:
            factors.append("Common attack vector")
        
        # Port-based factors
        if event.port in self.COMMON_BACKDOOR_PORTS:
            factors.append("Known backdoor port")
        if event.port in self.EPHEMERAL_PORTS:
            factors.append("Unusual port for services")
        
        # History-based factors
        if history:
            if history.get('seen_count', 0) <= 2:
                factors.append("Recently appeared")
            if history.get('current_state') == 'closed':
                factors.append("Port reopened")
        else:
            factors.append("First time detected")
        
        # Version-based factors
        if not event.version:
            factors.append("Version unknown")
        
        if not factors:
            factors.append("Standard risk for this service")
        
        return factors