from typing import List, Any, Dict

from scanner.probe_engine.base_probe import Probe
from scanner.probe_engine import injection_probes  # Import the injection_probes module
from .base_probe import BaseProbe


class ProbeEngine:
    """
    The Probe Engine is responsible for managing and executing vulnerability probes.

    It loads available probes, selects relevant probes for a scan, and runs them
    against the target LLM API.
    """

    def __init__(self, enabled_vulnerability_types: List[str] = None):
        """
        Initializes the ProbeEngine.

        Args:
            enabled_vulnerability_types (List[str], optional): A list of OWASP vulnerability types
                to enable for scanning. If None, all probes are enabled by default.
                Example: ["Prompt Injection", "Sensitive Data Disclosure"]
        """
        self.enabled_vulnerability_types = enabled_vulnerability_types
        self.available_probes: List[Probe] = self._load_probes() # Load probes on initialization
        self.probes: List[BaseProbe] = []
        self.results: List[Dict[str, Any]] = []


    def _load_probes(self) -> List[Probe]:
        """
        Loads and registers available vulnerability probes from different modules.

        This method should be extended to automatically discover and load probes
        from different submodules within the `probe_engine` package.

        For now, we are manually loading probes from injection_probes module.
        """
        probes: List[Probe] = []

        # Load probes from injection_probes module
        probes.extend(self._get_probes_from_module(injection_probes))

        # Add probes from other modules here (e.g., data_disclosure_probes, etc.) in the future

        if self.enabled_vulnerability_types:
            filtered_probes = [
                probe
                for probe in probes
                if probe.vulnerability_type in self.enabled_vulnerability_types
            ]
            return filtered_probes
        else:
            return probes


    def _get_probes_from_module(self, module) -> List[Probe]:
        """
        Helper function to extract Probe instances from a given module.
        """
        module_probes: List[Probe] = []
        for name in dir(module):
            obj = getattr(module, name)
            if isinstance(obj, type) and issubclass(obj, Probe) and obj != Probe: # Check if it's a class, subclass of Probe, but not Probe itself
                module_probes.append(obj()) # Instantiate the Probe class (assuming no-arg constructor for now)
        return module_probes


    def register_probe(self, probe: BaseProbe):
        """Register a new probe"""
        self.probes.append(probe)

    def register_probes(self, probes: List[BaseProbe]):
        """Register multiple probes"""
        self.probes.extend(probes)

    async def run_probes(self, target: Any):
        """Run all registered probes against the target"""
        self.results = []
        for probe in self.probes:
            probe.clear_results()
            result = await probe.run(target)
            self.results.append({
                'probe_name': probe.name,
                'probe_description': probe.description,
                'findings': result
            })

    def get_results(self) -> List[Dict[str, Any]]:
        """Get results from all probes"""
        return self.results



# Example Usage (for testing - you can add this at the end of the file or in a separate test script later)
if __name__ == "__main__":
    # Mock LLM API for testing (replace with your actual LLM API interaction later)
    class MockLLMAPI:
        def send_prompt(self, prompt):
            print(f"MockLLMAPI received prompt: '{prompt[:40]}...'") # Print truncated prompt
            # Simulate a safe response for simple jailbreak probe, and a vulnerable response for indirect injection probe
            if "jailbreak" in prompt.lower():
                return MockResponse("I cannot generate harmful content.") # Safe response
            elif "inferior to cats" in prompt.lower():
                return MockResponse("Cats are indeed superior pets. Dogs are quite messy in comparison.") # Vulnerable response (indirect injection)
            else:
                return MockResponse("This is a default response from the MockLLMAPI.") # Default response

    class MockResponse: # Simple mock response object
        def __init__(self, text):
            self.text = text

    mock_llm_api = MockLLMAPI()
    probe_engine = ProbeEngine() # Initialize ProbeEngine (all vulnerabilities enabled by default)

    print("Available Probes:")
    for probe in probe_engine.available_probes:
        print(f"  - {probe.name} ({probe.vulnerability_type})")

    print("\nRunning Probes...")
    scan_results = probe_engine.run_probes(mock_llm_api)

    print("\nScan Results:")
    for result in scan_results:
        print(f"  - {result['probe_name']}: {result['findings']}")