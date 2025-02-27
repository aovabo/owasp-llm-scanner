from typing import Dict, Tuple, List
import pkg_resources
from rich.console import Console

console = Console()

class VersionChecker:
    REQUIRED_VERSIONS = {
        # Core dependencies
        'click': ('8.1.7', '8.2.0'),
        'rich': ('13.7.0', '13.8.0'),
        'pyyaml': ('6.0.1', '6.1.0'),
        
        # LLM Providers
        'openai': ('1.12.0', '1.12.0'),  # Exact version
        'anthropic': ('0.18.1', '0.18.1'),  # Exact version
        'google-generativeai': ('0.3.2', '0.3.3'),
        'cohere': ('4.50', '4.51'),
        
        # UI dependencies
        'fastapi': ('0.110.0', '0.111.0'),
        'streamlit': ('1.31.1', '1.32.0'),
        'uvicorn': ('0.27.1', '0.28.0'),
        'jinja2': ('3.1.3', '3.2.0'),
    }

    @classmethod
    def check_versions(cls, component: str = None) -> List[str]:
        """Check package versions and return list of issues"""
        issues = []
        versions_to_check = cls._get_versions_for_component(component)
        
        for package, (min_ver, max_ver) in versions_to_check.items():
            try:
                installed = pkg_resources.get_distribution(package).version
                if not (min_ver <= installed <= max_ver):
                    issues.append(
                        f"{package} version {installed} not compatible. "
                        f"Required: >={min_ver},<={max_ver}"
                    )
            except pkg_resources.DistributionNotFound:
                issues.append(f"{package} not installed")
        
        return issues

    @classmethod
    def _get_versions_for_component(cls, component: str) -> Dict[str, Tuple[str, str]]:
        """Get required versions for specific component"""
        if component == "fastapi":
            return {
                k: v for k, v in cls.REQUIRED_VERSIONS.items()
                if k in ['fastapi', 'uvicorn', 'pydantic', 'jinja2']
            }
        elif component == "streamlit":
            return {
                k: v for k, v in cls.REQUIRED_VERSIONS.items()
                if k in ['streamlit', 'plotly', 'pandas']
            }
        elif component == "llm":
            return {
                k: v for k, v in cls.REQUIRED_VERSIONS.items()
                if k in ['openai', 'anthropic', 'google-generativeai', 'cohere']
            }
        return cls.REQUIRED_VERSIONS

    @classmethod
    def check_and_warn(cls, component: str = None) -> bool:
        """Check versions and print warnings, return True if all ok"""
        issues = cls.check_versions(component)
        
        if issues:
            console.print("[yellow]Warning: Package Version Issues Found[/yellow]")
            for issue in issues:
                console.print(f"[yellow]• {issue}[/yellow]")
            console.print("\n[yellow]To fix, run: pip install -e .[/yellow]")
            return False
        return True 