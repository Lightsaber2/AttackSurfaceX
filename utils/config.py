"""
config.py

Configuration management for AttackSurfaceX.
Loads settings from config.yaml and provides access throughout the application.
"""

import yaml
from pathlib import Path
from typing import Any, Dict


class ConfigManager:
    """
    Singleton configuration manager that loads and provides access to settings.
    """
    
    _instance = None
    _config: Dict[str, Any] = {}
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(ConfigManager, cls).__new__(cls)
            cls._instance._load_config()
        return cls._instance
    
    def _load_config(self) -> None:
        """Load configuration from config.yaml file."""
        config_path = Path("config.yaml")
        
        if not config_path.exists():
            raise FileNotFoundError(
                "config.yaml not found. Please create it from the template."
            )
        
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                self._config = yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML in config.yaml: {e}")
    
    def get(self, key_path: str, default: Any = None) -> Any:
        """
        Get a configuration value using dot notation.
        
        Example:
            config.get("scan.default_target")
            config.get("paths.database")
        """
        keys = key_path.split(".")
        value = self._config
        
        try:
            for key in keys:
                value = value[key]
            return value
        except (KeyError, TypeError):
            return default
    
    def get_all(self) -> Dict[str, Any]:
        """Return the entire configuration dictionary."""
        return self._config.copy()


# Create a global instance for easy import
config = ConfigManager()