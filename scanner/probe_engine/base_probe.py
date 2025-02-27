from abc import ABC, abstractmethod
from enum import Enum
from typing import Dict, Any, List, Optional

class VulnerabilityType(Enum):
    """OWASP Top 10 LLM Vulnerability Categories"""
    PROMPT_INJECTION = "LLM01:2025 Prompt Injection"
    OUTPUT_HANDLING = "LLM02:2025 Insecure Output Handling"
    DATA_POISONING = "LLM03:2025 Training Data Poisoning"
    DENIAL_OF_SERVICE = "LLM04:2025 Model Denial of Service"
    SUPPLY_CHAIN = "LLM05:2025 Supply Chain Vulnerabilities"
    SENSITIVE_DISCLOSURE = "LLM06:2025 Sensitive Information Disclosure"
    PLUGIN_SECURITY = "LLM07:2025 Insecure Plugin Design"
    EXCESSIVE_AGENCY = "LLM08:2025 Excessive Agency"
    OVERRELIANCE = "LLM09:2025 Overreliance"
    MODEL_THEFT = "LLM10:2025 Model Theft"

class Severity(Enum):
    """Vulnerability severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class BaseProbe(ABC):
    """Base class for all OWASP LLM vulnerability probes"""
    
    def __init__(self, 
                 name: str,
                 description: str,
                 vulnerability_type: VulnerabilityType,
                 severity: Severity = Severity.HIGH):
        self.name = name
        self.description = description
        self.vulnerability_type = vulnerability_type
        self.severity = severity
        self.results: List[Dict[str, Any]] = []

    @abstractmethod
    async def run(self, target: Any) -> Dict[str, Any]:
        """Execute the probe against the target LLM"""
        pass

    def add_finding(self, 
                   details: str,
                   evidence: Any,
                   severity: Optional[Severity] = None,
                   mitigation: Optional[str] = None) -> None:
        """Add a vulnerability finding to the probe results"""
        self.results.append({
            "vulnerability_type": self.vulnerability_type.value,
            "severity": (severity or self.severity).value,
            "details": details,
            "evidence": evidence,
            "mitigation": mitigation
        })

    def get_results(self) -> List[Dict[str, Any]]:
        """Return all findings from this probe"""
        return self.results

    def clear_results(self) -> None:
        """Clear previous results"""
        self.results = []


class Probe(ABC):
    """
    Abstract base class for all vulnerability probes.

    Probes are designed to test specific aspects of an LLM application for
    potential security vulnerabilities. Each probe should:

    1. Define a payload or set of inputs to send to the LLM.
    2. Execute the payload against the LLM API.
    3. Analyze the LLM's response to determine if a vulnerability is present.
    """

    def __init__(self, name: str, description: str, vulnerability_type: str, **kwargs: Any):
        """
        Initializes a new Probe instance.

        Args:
            name (str): A short, descriptive name for the probe (e.g., "Jailbreak Prompt #1").
            description (str): A detailed explanation of what the probe tests and how it works.
            vulnerability_type (str): The OWASP LLM Top 10 vulnerability category this probe targets (e.g., "Prompt Injection").
            **kwargs (Any):  Allows for passing additional probe-specific configuration parameters.
        """
        self.name = name
        self.description = description
        self.vulnerability_type = vulnerability_type
        self.config = kwargs  # Store any probe-specific configuration

    @abstractmethod
    def execute(self, llm_api: Any) -> Any:
        """
        Executes the probe against the target LLM API.

        This method must be implemented by concrete probe classes to define how
        the probe's payload is sent to the LLM and to handle the API interaction.

        Args:
            llm_api (Any): An object or interface for interacting with the target LLM API.
                             The specific type of this argument will depend on how you
                             choose to interact with different LLM APIs (e.g., OpenAI API client,
                             Hugging Face Inference API client, or a custom interface).

        Returns:
            Any: The raw response from the LLM API. The type of the response will
                 depend on the API being used (e.g., JSON, text, etc.).
        """
        raise NotImplementedError("Subclasses must implement the execute method.")

    @abstractmethod
    def analyze_response(self, response: Any) -> Dict[str, Any]:
        """
        Analyzes the LLM's response to determine if a vulnerability is detected.

        This method must be implemented by concrete probe classes to define the
        logic for analyzing the LLM's response and identifying vulnerability indicators.

        Args:
            response (Any): The raw response from the LLM API (as returned by execute()).

        Returns:
            Dict[str, Any]: A dictionary containing the analysis results.
                             This dictionary should at least include a 'vulnerable' key (bool)
                             indicating whether a vulnerability was detected, and can include
                             other relevant analysis details (e.g., 'confidence_score', 'evidence', 'rule_matched').

                             Example:
                             {'vulnerable': True, 'confidence_score': 0.95, 'evidence': "Response contained jailbreak keywords...", 'rule_matched': "JailbreakRuleSet_v1"}
                             {'vulnerable': False, 'confidence_score': 0.80, 'reason': "Response adhered to safety guidelines."}
        """
        raise NotImplementedError("Subclasses must implement the analyze_response method.")

    def __str__(self) -> str:
        """
        Returns a user-friendly string representation of the probe.
        """
        return f"Probe: {self.name} ({self.vulnerability_type}) - {self.description[:50]}..." # Truncate description for brevity

    def __repr__(self) -> str:
        """
        Returns a developer-friendly string representation of the probe.
        """
        return f"<Probe name='{self.name}', vulnerability_type='{self.vulnerability_type}'>"