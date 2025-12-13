"""
diff.py

Detects attack surface changes between two scans.
"""

import sqlite3
from typing import Dict, Set, Tuple


class ChangeDetector:
    """
    Compares scan results to detect attack surface changes.
    """

    def __init__(self, db_path: str = "attack_surface.db") -> None:
        self.db_path = db_path

    def _get_ports_for_scan(self, scan_id: int) -> Set[Tuple[str, int]]:
        """
        Retrieve (host, port) pairs for a given scan.
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT host, port
                FROM port_events
                WHERE scan_id = ?
                AND state = 'open'
                """,
                (scan_id,),
            )
            return set(cursor.fetchall())

    def detect_changes(self, old_scan_id: int, new_scan_id: int) -> Dict[str, Set[Tuple[str, int]]]:
        """
        Compare two scans and detect changes.

        Returns:
            Dict with keys: 'opened_ports', 'closed_ports'
        """
        old_ports = self._get_ports_for_scan(old_scan_id)
        new_ports = self._get_ports_for_scan(new_scan_id)

        return {
            "opened_ports": new_ports - old_ports,
            "closed_ports": old_ports - new_ports,
        }
