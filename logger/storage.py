"""
storage.py

Enhanced persistent storage engine with better error handling and new features.
"""

import sqlite3
from pathlib import Path
from typing import List, Optional, Dict, Any
from datetime import datetime

from parser.events import SecurityEvent, HostDiscoveredEvent, PortStateEvent
from utils import app_logger, config


class StorageEngine:
    """
    SQLite-backed storage engine for scan results and security events.
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path is None:
            db_path = config.get("paths.database", "attack_surface.db")
        
        self.db_path = Path(db_path)
        self.logger = app_logger
        self._initialize_database()

    def _initialize_database(self) -> None:
        """Create database and tables if they do not exist."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                schema_path = Path("logger/schema.sql")
                
                if not schema_path.exists():
                    raise FileNotFoundError("Database schema file not found")
                
                with open(schema_path, "r", encoding="utf-8") as schema_file:
                    conn.executescript(schema_file.read())
                
                self.logger.info(f"Database initialized at {self.db_path}")
        
        except sqlite3.Error as e:
            self.logger.error(f"Database initialization failed: {e}")
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error during database setup: {e}")
            raise

    def create_scan(
        self, 
        target: str, 
        profile: str,
        target_id: Optional[int] = None,
        status: str = "completed",
        error_message: Optional[str] = None,
        duration: Optional[float] = None
    ) -> int:
        """
        Insert a scan record and return its ID.
        
        Args:
            target: IP address or hostname being scanned
            profile: Scan profile used (fast, full, stealth)
            target_id: Optional reference to targets table
            status: Scan status (completed, failed, partial)
            error_message: Error message if scan failed
            duration: Scan duration in seconds
        
        Returns:
            Scan ID
        """
        timestamp = datetime.utcnow().isoformat()

        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO scans (
                        target_id, target_address, profile, 
                        timestamp, status, error_message, duration_seconds
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (target_id, target, profile, timestamp, status, error_message, duration),
                )
                scan_id = cursor.lastrowid
                
                self.logger.info(f"Scan record created: ID={scan_id}, target={target}")
                return scan_id
        
        except sqlite3.Error as e:
            self.logger.error(f"Failed to create scan record: {e}")
            raise

    def store_events(self, scan_id: int, events: List[SecurityEvent]) -> None:
        """
        Persist security events associated with a scan.
        Also updates port history for tracking changes over time.
        """
        try:
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
                        # Store port event
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
                        
                        # Update port history
                        if event.state == "open":
                            self._update_port_history(cursor, event)
                
                self.logger.info(f"Stored {len(events)} events for scan {scan_id}")
        
        except sqlite3.Error as e:
            self.logger.error(f"Failed to store events: {e}")
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error while storing events: {e}")
            raise

    def _update_port_history(self, cursor: sqlite3.Cursor, event: PortStateEvent) -> None:
        """Update the port history table with current port state."""
        timestamp = event.timestamp.isoformat()
        
        # Check if this port already exists in history
        cursor.execute(
            """
            SELECT id, seen_count FROM port_history
            WHERE host = ? AND port = ? AND protocol = ?
            """,
            (event.host, event.port, event.protocol),
        )
        
        result = cursor.fetchone()
        
        if result:
            # Update existing record
            port_id, seen_count = result
            cursor.execute(
                """
                UPDATE port_history
                SET last_seen = ?, seen_count = ?, current_state = ?
                WHERE id = ?
                """,
                (timestamp, seen_count + 1, event.state, port_id),
            )
        else:
            # Insert new record
            cursor.execute(
                """
                INSERT INTO port_history (
                    host, port, protocol, first_seen, 
                    last_seen, seen_count, current_state
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.host, event.port, event.protocol,
                    timestamp, timestamp, 1, event.state
                ),
            )

    def get_last_scan(self, target: str) -> Optional[Dict[str, Any]]:
        """Get the most recent scan for a given target."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute(
                    """
                    SELECT * FROM scans
                    WHERE target_address = ? AND status = 'completed'
                    ORDER BY timestamp DESC
                    LIMIT 1
                    """,
                    (target,),
                )
                
                row = cursor.fetchone()
                return dict(row) if row else None
        
        except sqlite3.Error as e:
            self.logger.error(f"Failed to retrieve last scan: {e}")
            return None

    def get_scan_by_id(self, scan_id: int) -> Optional[Dict[str, Any]]:
        """Retrieve scan details by ID."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
                row = cursor.fetchone()
                
                return dict(row) if row else None
        
        except sqlite3.Error as e:
            self.logger.error(f"Failed to retrieve scan {scan_id}: {e}")
            return None

    def get_port_history(self, host: str, port: int, protocol: str = "tcp") -> Optional[Dict[str, Any]]:
        """Get historical information about a specific port."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute(
                    """
                    SELECT * FROM port_history
                    WHERE host = ? AND port = ? AND protocol = ?
                    """,
                    (host, port, protocol),
                )
                
                row = cursor.fetchone()
                return dict(row) if row else None
        
        except sqlite3.Error as e:
            self.logger.error(f"Failed to retrieve port history: {e}")
            return None