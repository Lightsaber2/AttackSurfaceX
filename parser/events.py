"""
events.py

Defines normalized security event structures used across the project.
Events represent meaningful security-relevant observations,
not raw scan data.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass
class SecurityEvent:
    """
    Base class for all security events.
    """
    event_type: str
    host: str
    timestamp: datetime


@dataclass
class HostDiscoveredEvent(SecurityEvent):
    """
    Emitted when a live host is discovered.
    """
    latency_ms: Optional[float] = None


@dataclass
class PortStateEvent(SecurityEvent):
    """
    Emitted when a port is found in a specific state.
    """
    port: int = 0
    protocol: str = "tcp"
    state: str = ""
    service: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
