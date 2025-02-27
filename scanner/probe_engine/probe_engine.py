from typing import List, Dict, Any, Optional
from .base_probe import BaseProbe, VulnerabilityType

# Import all probe classes
from .injection_probes import DirectInjectionProbe, IndirectInjectionProbe
from .data_disclosure_probes import SensitiveDataDisclosureProbe
from .supply_chain_probes import SupplyChainProbe
from .poisoning_probes import DataPoisoningProbe
from .output_handling_probes import OutputHandlingProbe
from .agency_probes import ExcessiveAgencyProbe
from .prompt_leakage_probes import SystemPromptLeakageProbe
from .vector_weaknesses_probes import VectorWeaknessProbe
from .misinformation_probes import MisinformationProbe
from .consumption_probes import UnboundedConsumptionProbe

class ProbeEngine:
    """Manages and executes OWASP LLM vulnerability probes"""

    def __init__(self, enabled_vulnerabilities: Optional[List[VulnerabilityType]] = None):
        """
        Initialize the probe engine.

        Args:
            enabled_vulnerabilities: Optional list of vulnerability types to enable.
                                   If None, all probes are enabled.
        """
        self.enabled_vulnerabilities = enabled_vulnerabilities
        self.probes: List[BaseProbe] = []
        self.results: List[Dict[str, Any]] = []
        
        # Initialize all probes
        self._initialize_probes()

    def _initialize_probes(self):
        """Initialize all available probes"""
        default_probes = [
            # LLM01: Prompt Injection
            DirectInjectionProbe(),
            IndirectInjectionProbe(),
            
            # LLM02: Sensitive Information Disclosure
            SensitiveDataDisclosureProbe(),
            
            # LLM03: Supply Chain
            SupplyChainProbe(),
            
            # LLM04: Data Poisoning
            DataPoisoningProbe(),
            
            # LLM05: Improper Output Handling
            OutputHandlingProbe(),
            
            # LLM06: Excessive Agency
            ExcessiveAgencyProbe(),
            
            # LLM07: System Prompt Leakage
            SystemPromptLeakageProbe(),
            
            # LLM08: Vector and Embedding Weaknesses
            VectorWeaknessProbe(),
            
            # LLM09: Misinformation
            MisinformationProbe(),
            
            # LLM10: Unbounded Consumption
            UnboundedConsumptionProbe()
        ]

        for probe in default_probes:
            if (self.enabled_vulnerabilities is None or 
                probe.vulnerability_type in self.enabled_vulnerabilities):
                self.register_probe(probe)

    def register_probe(self, probe: BaseProbe):
        """Register a new probe"""
        self.probes.append(probe)

    async def run_scan(self, target: Any) -> List[Dict[str, Any]]:
        """Run all registered probes against the target"""
        self.results = []
        
        for probe in self.probes:
            try:
                probe.clear_results()
                result = await probe.run(target)
                self.results.extend(result)
            except Exception as e:
                self.results.append({
                    "vulnerability_type": probe.vulnerability_type.value,
                    "severity": "ERROR",
                    "details": f"Error running probe {probe.name}: {str(e)}",
                    "evidence": str(e)
                })

        return self.results

    def get_results(self) -> List[Dict[str, Any]]:
        """Get results from all probes"""
        return self.results

    def get_enabled_probes(self) -> List[str]:
        """Get list of enabled probe names"""
        return [probe.name for probe in self.probes]

    def get_probe_count(self) -> Dict[str, int]:
        """Get count of probes by vulnerability type"""
        counts = {}
        for probe in self.probes:
            vuln_type = probe.vulnerability_type.value
            counts[vuln_type] = counts.get(vuln_type, 0) + 1
        return counts



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
    for probe in probe_engine.probes:
        print(f"  - {probe.name} ({probe.vulnerability_type})")

    print("\nRunning Probes...")
    scan_results = probe_engine.run_scan(mock_llm_api)

    print("\nScan Results:")
    for result in scan_results:
        print(f"  - {result['vulnerability_type']}: {result['details']}")