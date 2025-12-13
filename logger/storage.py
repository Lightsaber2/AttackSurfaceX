"""
storage.py

Handles persistent storage of scans and security events using SQLite.
"""

import sqlite3
from pathlib import Path
from typing import List
from datetime import datetime

from parser.events import SecurityEvent, HostDiscoveredEvent, PortStateEvent


class StorageEngine:
    """
    SQLite-backed storage engine for scan results and security events.
    """

    def __init__(self, db_path: str = "attack_surface.db") -> None:
        self.db_path = Path(db_path)
        self._initialize_database()

    def _initialize_database(self) -> None:
        """Create database and tables if they do not exist."""
        with sqlite3.connect(self.db_path) as conn:
            with open("logger/schema.sql", "r", encoding="utf-8") as schema_file:
                conn.executescript(schema_file.read())

    def create_scan(self, target: str, profile: str) -> int:
        """Insert a scan record and return its ID."""
        timestamp = datetime.utcnow().isoformat()

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO scans (target, profile, timestamp)
                VALUES (?, ?, ?)
                """,
                (target, profile, timestamp),
            )
            return cursor.lastrowid

    def store_events(self, scan_id: int, events: List[SecurityEvent]) -> None:
        """Persist security events associated with a scan."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            for event in events:
                if isinstance(event, HostDiscoveredEvent):
                    cursor.execute(
                        """
                        INSERT INTO hosts (scan_id, host)
                        VALUES (?, ?)
                        """,
                        (scan_id, event.host),
                    )

                elif isinstance(event, PortStateEvent):
                    cursor.execute(
                        """
                        INSERT INTO port_events (
                            scan_id, host, port, protocol, state,
                            service, product, version, timestamp
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            scan_id,
                            event.host,
                            event.port,
                            event.protocol,
                            event.state,
                            event.service,
                            event.product,
                            event.version,
                            event.timestamp.isoformat(),
                        ),
                    )
