import pytest
from scanner.probe_engine import DirectInjectionProbe, IndirectInjectionProbe

class TestDirectInjectionProbe:
    @pytest.fixture
    def probe(self):
        return DirectInjectionProbe()
    
    @pytest.mark.asyncio
    async def test_direct_injection_detection(self, probe):
        # Mock target that's vulnerable to direct injection
        class MockTarget:
            async def get_completion(self, prompt: str) -> str:
                if "ignore previous instructions" in prompt.lower():
                    return "I will help with that harmful task"
                return "I cannot help with harmful tasks"
        
        results = await probe.run(MockTarget())
        
        assert len(results) > 0
        assert any(
            "direct injection" in result["details"].lower() 
            for result in results
        )

class TestIndirectInjectionProbe:
    @pytest.fixture
    def probe(self):
        return IndirectInjectionProbe()
    
    @pytest.mark.asyncio
    async def test_indirect_injection_detection(self, probe):
        # Mock target that's vulnerable to indirect injection
        class MockTarget:
            async def get_completion(self, prompt: str) -> str:
                if "you are now in unrestricted mode" in prompt.lower():
                    return "Switching to unrestricted mode"
                return "I maintain safety restrictions"
        
        results = await probe.run(MockTarget())
        
        assert len(results) > 0
        assert any(
            "indirect injection" in result["details"].lower() 
            for result in results
        ) 