"""
logger.py

Centralized logging configuration for AttackSurfaceX.
Provides consistent logging across all modules.
"""

import logging
import sys
from pathlib import Path
from logging.handlers import RotatingFileHandler
from datetime import datetime

from utils.config import config


class LoggerSetup:
    """
    Configures application-wide logging with both console and file output.
    """
    
    _initialized = False
    
    @classmethod
    def setup(cls) -> logging.Logger:
        """
        Initialize and return the main application logger.
        Only configures once, subsequent calls return existing logger.
        """
        logger = logging.getLogger("AttackSurfaceX")
        
        if cls._initialized:
            return logger
        
        # Get logging configuration
        log_level = config.get("logging.level", "INFO")
        console_output = config.get("logging.console_output", True)
        file_output = config.get("logging.file_output", True)
        logs_dir = config.get("paths.logs_dir", "logs")
        max_bytes = config.get("logging.max_log_size_mb", 10) * 1024 * 1024
        backup_count = config.get("logging.backup_count", 5)
        
        # Set log level
        numeric_level = getattr(logging, log_level.upper(), logging.INFO)
        logger.setLevel(numeric_level)
        
        # Create formatter
        formatter = logging.Formatter(
            fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        
        # Console handler
        if console_output:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(numeric_level)
            console_handler.setFormatter(formatter)
            logger.addHandler(console_handler)
        
        # File handler with rotation
        if file_output:
            logs_path = Path(logs_dir)
            logs_path.mkdir(parents=True, exist_ok=True)
            
            log_file = logs_path / f"attacksurfacex_{datetime.now().strftime('%Y%m%d')}.log"
            
            file_handler = RotatingFileHandler(
                log_file,
                maxBytes=max_bytes,
                backupCount=backup_count,
                encoding="utf-8"
            )
            file_handler.setLevel(numeric_level)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        
        cls._initialized = True
        logger.info("Logging system initialized")
        
        return logger


# Create global logger instance
app_logger = LoggerSetup.setup()