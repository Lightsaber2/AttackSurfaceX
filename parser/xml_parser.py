"""
xml_parser.py

Parses Nmap XML output files and converts findings into
structured security events.
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


class NmapXMLParser:
    """
    Responsible for parsing Nmap XML files and emitting security events.
    """

    def parse(self, xml_path: str) -> List[SecurityEvent]:
        """
        Parse an Nmap XML file and extract security events.

        Args:
            xml_path (str): Path to Nmap XML output file.

        Returns:
            List[SecurityEvent]: List of extracted security events.
        """
        xml_file = Path(xml_path)

        if not xml_file.exists():
            raise FileNotFoundError(f"XML file not found: {xml_path}")

        tree = etree.parse(str(xml_file))
        root = tree.getroot()

        events: List[SecurityEvent] = []
        timestamp = datetime.utcnow()

        for host in root.findall("host"):
            address_elem = host.find("address")
            if address_elem is None:
                continue

            host_ip = address_elem.get("addr")

            # Host discovery event
            latency_elem = host.find("times")
            latency = None
            if latency_elem is not None:
                latency = float(latency_elem.get("srtt", 0)) / 1000

            events.append(
                HostDiscoveredEvent(
                    event_type="host_discovered",
                    host=host_ip,
                    timestamp=timestamp,
                    latency_ms=latency,
                )
            )

            ports_elem = host.find("ports")
            if ports_elem is None:
                continue

            for port in ports_elem.findall("port"):
                port_id = int(port.get("portid"))
                protocol = port.get("protocol")

                state_elem = port.find("state")
                if state_elem is None:
                    continue

                state = state_elem.get("state")

                service_elem = port.find("service")
                service = product = version = None

                if service_elem is not None:
                    service = service_elem.get("name")
                    product = service_elem.get("product")
                    version = service_elem.get("version")

                events.append(
                    PortStateEvent(
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
                )

        return events
