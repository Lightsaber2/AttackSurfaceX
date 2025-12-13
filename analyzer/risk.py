"""
risk.py

Assigns risk scores to port exposure events based on
service type and port characteristics.
"""

from typing import Dict, List

from parser.events import PortStateEvent


class RiskScorer:
    """
    Simple rule-based risk scoring engine.
    """

    # Base risk scores by service name
    SERVICE_RISK: Dict[str, int] = {
        "ftp": 8,
        "telnet": 9,
        "ssh": 4,
        "http": 3,
        "https": 2,
        "smtp": 5,
        "pop3": 6,
        "imap": 5,
        "pptp": 9,
        "rdp": 8,
        "smb": 9,
        "microsoft-ds": 9,
    }

    def score_event(self, event: PortStateEvent) -> int:
        """
        Assign a risk score to a single port event.
        """
        if event.state != "open":
            return 0

        # Base score from service type
        score = self.SERVICE_RISK.get(event.service, 2)

        # Extra risk for privileged ports
        if event.port < 1024:
            score += 1

        return min(score, 10)

    def score_events(self, events: List[PortStateEvent]) -> List[Dict]:
        """
        Score all port events and return risk summaries.
        """
        results = []

        for event in events:
            risk = self.score_event(event)

            if risk > 0:
                results.append(
                    {
                        "host": event.host,
                        "port": event.port,
                        "service": event.service,
                        "risk": risk,
                    }
                )

        return results