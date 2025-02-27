from typing import Dict, Any, Optional
import yaml
from pathlib import Path
from dataclasses import dataclass

@dataclass
class ProbeConfig:
    enabled: bool = True
    timeout: int = 30
    max_retries: int = 3
    custom_settings: Dict[str, Any] = None

@dataclass
class ScanConfig:
    target: Dict[str, Any]
    probes: Dict[str, ProbeConfig]
    output: Dict[str, Any]
    analysis: Dict[str, Any]
    monitoring: Dict[str, Any]

class ConfigManager:
    """Manages scan configuration"""
    
    DEFAULT_CONFIG = {
        "target": {
            "timeout": 300,
            "max_tokens": 2000,
            "temperature": 0.7
        },
        "probes": {
            "prompt_injection": {
                "enabled": True,
                "timeout": 30
            },
            "data_disclosure": {
                "enabled": True,
                "timeout": 30
            }
            # ... other probes ...
        },
        "output": {
            "format": "markdown",
            "include_evidence": True,
            "save_artifacts": True
        },
        "analysis": {
            "risk_threshold": 7,
            "enable_visualizations": True,
            "track_history": True
        },
        "monitoring": {
            "enabled": False,
            "interval": 3600,
            "alert_threshold": "HIGH"
        }
    }
    
    def __init__(self, config_path: Optional[Path] = None):
        self.config_path = config_path
        self.config = self.load_config()
    
    def load_config(self) -> ScanConfig:
        """Load configuration from file or use defaults"""
        config_data = self.DEFAULT_CONFIG.copy()
        
        if self.config_path and self.config_path.exists():
            with open(self.config_path) as f:
                file_config = yaml.safe_load(f)
                # Deep merge with defaults
                config_data = self._merge_configs(config_data, file_config)
        
        return ScanConfig(
            target=config_data["target"],
            probes={
                name: ProbeConfig(**settings)
                for name, settings in config_data["probes"].items()
            },
            output=config_data["output"],
            analysis=config_data["analysis"],
            monitoring=config_data["monitoring"]
        )
    
    def _merge_configs(self, base: Dict, override: Dict) -> Dict:
        """Deep merge two configuration dictionaries"""
        merged = base.copy()
        
        for key, value in override.items():
            if (
                key in merged and 
                isinstance(merged[key], dict) and 
                isinstance(value, dict)
            ):
                merged[key] = self._merge_configs(merged[key], value)
            else:
                merged[key] = value
        
        return merged
    
    def save_config(self, config_path: Optional[Path] = None):
        """Save current configuration to file"""
        save_path = config_path or self.config_path
        if save_path:
            with open(save_path, 'w') as f:
                yaml.dump(self.config.__dict__, f, default_flow_style=False) 