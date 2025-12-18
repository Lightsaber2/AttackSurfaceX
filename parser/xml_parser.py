"""
xml_parser.py

Enhanced Nmap XML parser with better error handling and validation.
"""

from datetime import datetime
from pathlib import Path
from typing import List

from lxml import etree

from parser.events import (
    SecurityEvent,
    HostDiscoveredEvent,
    PortStateEvent,
)
from utils import app_logger


class ParseError(Exception):
    """Raised when XML parsing fails."""
    pass


class NmapXMLParser:
    """
    Parses Nmap XML output files and converts findings into structured security events.
    """

    def __init__(self):
        self.logger = app_logger

    def parse(self, xml_path: str) -> List[SecurityEvent]:
        """
        Parse an Nmap XML file and extract security events.

        Args:
            xml_path (str): Path to Nmap XML output file.

        Returns:
            List[SecurityEvent]: List of extracted security events.
        
        Raises:
            FileNotFoundError: If XML file doesn't exist
            ParseError: If XML is malformed or invalid
        """
        xml_file = Path(xml_path)

        if not xml_file.exists():
            error_msg = f"XML file not found: {xml_path}"
            self.logger.error(error_msg)
            raise FileNotFoundError(error_msg)

        try:
            self.logger.info(f"Parsing XML file: {xml_file.name}")
            tree = etree.parse(str(xml_file))
            root = tree.getroot()
            
            # Validate that this is an Nmap XML file
            if root.tag != "nmaprun":
                raise ParseError("Invalid Nmap XML file: missing nmaprun root element")
            
            events = self._extract_events(root)
            
            self.logger.info(f"Successfully parsed {len(events)} events from {xml_file.name}")
            return events
        
        except etree.XMLSyntaxError as e:
            error_msg = f"XML syntax error: {e}"
            self.logger.error(error_msg)
            raise ParseError(error_msg)
        
        except Exception as e:
            error_msg = f"Unexpected error during parsing: {e}"
            self.logger.error(error_msg, exc_info=True)
            raise ParseError(error_msg)

    def _extract_events(self, root: etree.Element) -> List[SecurityEvent]:
        """Extract security events from parsed XML root element."""
        events: List[SecurityEvent] = []
        timestamp = datetime.utcnow()

        hosts_found = root.findall("host")
        self.logger.debug(f"Found {len(hosts_found)} hosts in scan results")

        for host in hosts_found:
            try:
                host_events = self._parse_host(host, timestamp)
                events.extend(host_events)
            except Exception as e:
                # Log error but continue parsing other hosts
                self.logger.warning(f"Error parsing host: {e}")
                continue

        return events

    def _parse_host(self, host: etree.Element, timestamp: datetime) -> List[SecurityEvent]:
        """Parse a single host element and extract events."""
        events: List[SecurityEvent] = []
        
        # Extract IP address
        address_elem = host.find("address")
        if address_elem is None:
            self.logger.warning("Host missing address element, skipping")
            return events

        host_ip = address_elem.get("addr")
        if not host_ip:
            self.logger.warning("Host address is empty, skipping")
            return events

        # Host discovery event with latency information
        latency_elem = host.find("times")
        latency = None
        if latency_elem is not None:
            try:
                srtt = latency_elem.get("srtt", "0")
                latency = float(srtt) / 1000  # Convert to milliseconds
            except (ValueError, TypeError):
                self.logger.debug(f"Could not parse latency for {host_ip}")

        events.append(
            HostDiscoveredEvent(
                event_type="host_discovered",
                host=host_ip,
                timestamp=timestamp,
                latency_ms=latency,
            )
        )

        # Parse port information
        ports_elem = host.find("ports")
        if ports_elem is None:
            self.logger.debug(f"No ports found for host {host_ip}")
            return events

        for port in ports_elem.findall("port"):
            try:
                port_event = self._parse_port(port, host_ip, timestamp)
                if port_event:
                    events.append(port_event)
            except Exception as e:
                self.logger.warning(f"Error parsing port for {host_ip}: {e}")
                continue

        return events

    def _parse_port(
        self, 
        port: etree.Element, 
        host_ip: str, 
        timestamp: datetime
    ) -> PortStateEvent:
        """Parse a single port element."""
        try:
            port_id = int(port.get("portid"))
            protocol = port.get("protocol", "tcp")
        except (ValueError, TypeError) as e:
            raise ParseError(f"Invalid port ID: {e}")

        state_elem = port.find("state")
        if state_elem is None:
            raise ParseError("Port missing state element")

        state = state_elem.get("state", "unknown")

        # Extract service information
        service_elem = port.find("service")
        service = product = version = None

        if service_elem is not None:
            service = service_elem.get("name")
            product = service_elem.get("product")
            version = service_elem.get("version")

        return PortStateEvent(
            event_type="port_state",
            host=host_ip,
            timestamp=timestamp,
            port=port_id,
            protocol=protocol,
            state=state,
            service=service,
            product=product,
            version=version,
        )