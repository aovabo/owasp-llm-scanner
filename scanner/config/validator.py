from typing import Dict, Any, List
from dataclasses import dataclass
from pathlib import Path
import yaml

@dataclass
class ConfigValidationError:
    field: str
    message: str

class ConfigValidator:
    """Validates scanner configuration"""
    
    def validate_config(self, config: Dict[str, Any]) -> List[ConfigValidationError]:
        errors = []
        
        # Validate required sections
        required_sections = ["target", "probes", "output"]
        for section in required_sections:
            if section not in config:
                errors.append(
                    ConfigValidationError(section, f"Missing required section: {section}")
                )
        
        # Validate probe configurations
        if "probes" in config:
            for probe, settings in config["probes"].items():
                if not isinstance(settings, dict):
                    errors.append(
                        ConfigValidationError(
                            f"probes.{probe}",
                            "Probe settings must be a dictionary"
                        )
                    )
                elif "enabled" not in settings:
                    errors.append(
                        ConfigValidationError(
                            f"probes.{probe}",
                            "Missing required field: enabled"
                        )
                    )
        
        return errors 