"""
profiles.py

Defines reusable Nmap scan profiles with metadata.
"""

from typing import Dict, List

SCAN_PROFILES: Dict[str, Dict[str, List[str]]] = {
    "fast": {
        "description": "Fast scan of top 100 TCP ports",
        "flags": [
            "-T4",
            "--top-ports", "100",
        ],
    },
    "full": {
        "description": "Comprehensive full port scan with service detection",
        "flags": [
            "-p-",
            "-sV",
            "-T3",
        ],
    },
    "stealth": {
        "description": "Low-noise SYN scan without host discovery",
        "flags": [
            "-sS",
            "-Pn",
            "-T2",
        ],
    },
}
