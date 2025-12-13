"""
profiles.py

Defines reusable Nmap scan profiles.
Profiles abstract scan strategies away from execution logic.
"""

from typing import Dict, List

SCAN_PROFILES: Dict[str, List[str]] = {
    "fast": [
        "-T4",
        "--top-ports", "100",
    ],
    "full": [
        "-p-",
        "-sV",
        "-T3",
    ],
    "stealth": [
        "-sS",
        "-Pn",
        "-T2",
    ],
}
