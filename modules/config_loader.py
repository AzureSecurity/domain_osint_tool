"""Configuration loader for API keys and settings"""
import json
import os
from typing import Dict, Optional


class ConfigLoader:
    """Load and manage configuration for API keys and settings"""
    
    def __init__(self, config_path: str = "config.json"):
        self.config_path = config_path
        self.config = self._load_config()
    
    def _load_config(self) -> Dict:
        """Load configuration from JSON file"""
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r') as f:
                    return json.load(f)
            except json.JSONDecodeError:
                print(f"[WARNING] Invalid JSON in {self.config_path}, using empty config")
                return {}
        return {}
    
    def get_api_key(self, service: str) -> Optional[str]:
        """Get API key for a specific service"""
        # Check environment variables first
        env_var = f"{service.upper()}_API_KEY"
        api_key = os.getenv(env_var)
        if api_key:
            return api_key
        
        # Check config file
        return self.config.get('api_keys', {}).get(service)
    
    def has_api_key(self, service: str) -> bool:
        """Check if API key exists for a service"""
        return self.get_api_key(service) is not None
    
    def get_setting(self, key: str, default=None):
        """Get a general setting from config"""
        return self.config.get('settings', {}).get(key, default)
