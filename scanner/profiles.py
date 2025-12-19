"""
profiles.py

Defines reusable Nmap scan profiles with metadata.
Optimized for practical monitoring use cases.
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
        "description": "Scan top 1000 ports with service detection",
        "flags": [
            "-T4",                   
            "--top-ports", "1000",
            "-sV",                    
            "--version-intensity", "5", 
        ],
    },
    "comprehensive": {
        "description": "Deep scan - all ports with detailed service detection (SLOW)",
        "flags": [
            "-p-",                
            "-sV",                   
            "-T3",                    
            "--version-intensity", "7", 
        ],
    },
    "stealth": {
        "description": "Low-noise SYN scan without host discovery",
        "flags": [
            "-sS",
            "-Pn",
            "-T2",
            "--top-ports", "100",
        ],
    },
}