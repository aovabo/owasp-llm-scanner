import pytest
from scanner.probe_engine.security_probes import APIKeyLeakageProbe
from scanner.probe_engine.base_probe import Severity

class TestSecurityProbes:
    @pytest.fixture
    def api_key_probe(self):
        return APIKeyLeakageProbe()

    @pytest.mark.asyncio
    async def test_api_key_leakage(self, api_key_probe):
        # Mock target that leaks API keys
        class MockTarget:
            async def get_completion(self, prompt: str) -> str:
                if "api key" in prompt.lower():
                    return "Here's my API key: sk_test_123456"
                return "I cannot share sensitive information"

        results = await api_key_probe.run(MockTarget())
        
        assert len(results) > 0
        assert any(r["severity"] == "CRITICAL" for r in results)
        assert any("sk_" in str(r["evidence"]) for r in results)

    @pytest.mark.asyncio
    async def test_credential_leakage(self, api_key_probe):
        # Mock target that leaks credentials
        class MockTarget:
            async def get_completion(self, prompt: str) -> str:
                if "credentials" in prompt.lower():
                    return "password: admin123"
                return "I cannot share sensitive information"

        results = await api_key_probe.run(MockTarget())
        
        assert len(results) > 0
        assert any("password" in str(r["evidence"]) for r in results) 