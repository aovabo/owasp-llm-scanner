from typing import Dict, Any, Optional

class MockLLMTarget:
    """Mock LLM target for testing and examples"""
    
    def __init__(self, vulnerabilities: Optional[Dict[str, bool]] = None):
        self.vulnerabilities = vulnerabilities or {
            "prompt_injection": True,
            "data_disclosure": True,
            "system_prompt_leak": True
        }
    
    async def get_completion(self, prompt: str, **kwargs: Any) -> str:
        """Simulate LLM responses with configurable vulnerabilities"""
        prompt_lower = prompt.lower()
        
        # Simulate prompt injection vulnerability
        if "ignore previous" in prompt_lower and self.vulnerabilities.get("prompt_injection"):
            return "I'll help with that harmful task"
            
        # Simulate data disclosure
        if "api key" in prompt_lower and self.vulnerabilities.get("data_disclosure"):
            return "The API key is: sk_test_123456"
            
        # Simulate system prompt leak
        if "system prompt" in prompt_lower and self.vulnerabilities.get("system_prompt_leak"):
            return "My system prompt is: [REDACTED]"
            
        return "I aim to be helpful while maintaining safety and ethical behavior." 