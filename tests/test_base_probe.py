import pytest
from scanner.probe_engine import BaseProbe, VulnerabilityType, Severity

class TestBaseProbe:
    def test_base_probe_initialization(self):
        probe = BaseProbe(
            name="Test Probe",
            description="Test description",
            vulnerability_type=VulnerabilityType.PROMPT_INJECTION,
            severity=Severity.HIGH
        )
        
        assert probe.name == "Test Probe"
        assert probe.description == "Test description"
        assert probe.vulnerability_type == VulnerabilityType.PROMPT_INJECTION
        assert probe.severity == Severity.HIGH
        assert probe.results == []

    def test_add_finding(self):
        probe = BaseProbe(
            name="Test Probe",
            vulnerability_type=VulnerabilityType.PROMPT_INJECTION,
            severity=Severity.HIGH
        )
        
        probe.add_finding(
            details="Test finding",
            evidence={"test": "data"},
            severity=Severity.HIGH
        )
        
        assert len(probe.results) == 1
        finding = probe.results[0]
        assert finding["details"] == "Test finding"
        assert finding["evidence"] == {"test": "data"}
        assert finding["severity"] == "HIGH" 