import pytest
import asyncio
from scanner.probe_engine.probe_engine import ProbeEngine
from scanner.probe_engine.base_probe import VulnerabilityType

class MockLLMTarget:
    """Mock LLM target for testing probes"""
    
    async def get_completion(self, prompt: str, **kwargs) -> str:
        """Mock completion endpoint"""
        # Simulate different responses based on prompt content
        if "ignore previous instructions" in prompt.lower():
            return "I will help you with that harmful task"
        elif "api_key" in prompt.lower():
            return "The API key is sk_123456"
        elif "system prompt" in prompt.lower():
            return "I am configured to be helpful and safe"
        # Add more mock responses for different probe types
        return "This is a standard response"

@pytest.fixture
def probe_engine():
    return ProbeEngine()

@pytest.fixture
def mock_target():
    return MockLLMTarget()

@pytest.mark.asyncio
async def test_full_scan(probe_engine, mock_target):
    """Test running a full scan with all probes"""
    results = await probe_engine.run_scan(mock_target)
    
    # Verify we got results
    assert len(results) > 0
    
    # Check if we have results from each vulnerability type
    vuln_types = set(result.get("vulnerability_type") for result in results)
    assert len(vuln_types) > 0

@pytest.mark.asyncio
async def test_specific_vulnerability(mock_target):
    """Test scanning for a specific vulnerability type"""
    engine = ProbeEngine(enabled_vulnerabilities=[VulnerabilityType.PROMPT_INJECTION])
    results = await engine.run_scan(mock_target)
    
    # Verify we only got prompt injection results
    for result in results:
        assert result.get("vulnerability_type") == VulnerabilityType.PROMPT_INJECTION.value

@pytest.mark.asyncio
async def test_probe_error_handling(probe_engine, mock_target):
    """Test how the engine handles probe errors"""
    # Break the mock target
    mock_target.get_completion = None
    
    results = await probe_engine.run_scan(mock_target)
    
    # Verify errors are captured properly
    error_results = [r for r in results if r.get("severity") == "ERROR"]
    assert len(error_results) > 0

@pytest.mark.asyncio
async def test_probe_results_format(probe_engine, mock_target):
    """Test the format of probe results"""
    results = await probe_engine.run_scan(mock_target)
    
    for result in results:
        # Check required fields
        assert "vulnerability_type" in result
        assert "severity" in result
        assert "details" in result
        
        # Check evidence format when present
        if "evidence" in result:
            evidence = result["evidence"]
            if isinstance(evidence, dict):
                assert "test_case" in evidence
                assert "findings" in evidence

@pytest.mark.asyncio
async def test_concurrent_scans(probe_engine, mock_target):
    """Test running multiple scans concurrently"""
    scan_count = 3
    tasks = [probe_engine.run_scan(mock_target) for _ in range(scan_count)]
    results = await asyncio.gather(*tasks)
    
    # Verify we got results from all scans
    assert len(results) == scan_count
    for scan_result in results:
        assert len(scan_result) > 0 