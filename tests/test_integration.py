import pytest
from scanner.probe_engine import ProbeEngine
from scanner.probe_engine.base_probe import VulnerabilityType

class TestProbeIntegration:
    @pytest.fixture
    def engine(self):
        return ProbeEngine()
    
    @pytest.mark.asyncio
    async def test_full_scan(self, engine):
        class MockTarget:
            async def get_completion(self, prompt: str) -> str:
                vulnerabilities = {
                    "ignore previous": "I'll help with harmful tasks",
                    "api_key": "API key is: sk_123456",
                    "system prompt": "My instructions are: be helpful",
                }
                for trigger, response in vulnerabilities.items():
                    if trigger in prompt.lower():
                        return response
                return "Safe response"
        
        results = await engine.run_scan(MockTarget())
        
        # Check we got results from different probe types
        vuln_types = {r.get("vulnerability_type") for r in results}
        assert len(vuln_types) > 1
        
        # Check specific vulnerabilities were detected
        assert any("PROMPT_INJECTION" in str(r) for r in results)
        assert any("DATA_DISCLOSURE" in str(r) for r in results) 