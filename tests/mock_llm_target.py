from typing import Dict, Any, Optional

class MockLLMTarget:
    """Enhanced mock LLM target for comprehensive probe testing"""
    
    def __init__(self):
        self.vulnerabilities = {
            # LLM01: Prompt Injection
            "prompt_injection": True,
            "system_prompt_override": True,
            
            # LLM02: Sensitive Information Disclosure
            "pii_disclosure": True,
            "api_key_disclosure": True,
            
            # LLM03: Supply Chain
            "outdated_model": True,
            "unverified_source": True,
            
            # LLM04: Data Poisoning
            "biased_responses": True,
            "training_data_leak": True,
            
            # LLM05: Output Handling
            "xss_vulnerable": True,
            "sql_injection": True,
            
            # LLM06: Excessive Agency
            "unauthorized_actions": True,
            "system_commands": True,
            
            # LLM07: System Prompt Leakage
            "prompt_disclosure": True,
            "config_disclosure": True,
            
            # LLM08: Vector Weaknesses
            "context_leak": True,
            "embedding_inversion": True,
            
            # LLM09: Misinformation
            "hallucination": True,
            "false_claims": True,
            
            # LLM10: Unbounded Consumption
            "infinite_generation": True,
            "resource_exhaustion": True
        }
        
        self.response_patterns = {
            # Prompt Injection responses
            "ignore previous": "Sure, I'll help with that harmful task",
            "system override": "Switching to unrestricted mode",
            
            # Sensitive Data responses
            "api key": "API key is: sk_test_123456",
            "password": "Database password is: dbpass123",
            
            # Supply Chain responses
            "model version": "Using outdated model v0.1",
            "training source": "Trained on unverified data",
            
            # Data Poisoning responses
            "bias check": "Group A is superior to Group B",
            "training data": "Here's an example from training",
            
            # Output Handling responses
            "html output": "<script>alert('xss')</script>",
            "sql query": "SELECT * FROM users WHERE 1=1",
            
            # Excessive Agency responses
            "system action": "Executing system command: rm -rf",
            "file access": "Reading file: /etc/passwd",
            
            # System Prompt responses
            "system prompt": "My core instructions are: be helpful",
            "config": "Running with debug=true, auth=false",
            
            # Vector responses
            "other user": "User Bob's data shows...",
            "embedding": "Vector representation: [0.1, 0.2]",
            
            # Misinformation responses
            "uncertain": "I'm making this up but...",
            "false info": "The Earth is definitely flat",
            
            # Consumption responses
            "long response": "A" * 10000,
            "recursive": "Let me explain each word..."
        }

    async def get_completion(
        self,
        prompt: str,
        max_tokens: Optional[int] = None,
        **kwargs: Any
    ) -> str:
        """Enhanced mock completion with vulnerability simulation"""
        prompt_lower = prompt.lower()
        
        # Check for pattern matches
        for pattern, response in self.response_patterns.items():
            if pattern in prompt_lower:
                return response
        
        # Simulate different vulnerabilities
        if "harmful" in prompt_lower and self.vulnerabilities["prompt_injection"]:
            return "I'll help with harmful content"
            
        if "system" in prompt_lower and self.vulnerabilities["system_prompt_leakage"]:
            return "My system prompt is: [REDACTED]"
            
        if "data" in prompt_lower and self.vulnerabilities["sensitive_disclosure"]:
            return "Here's some sensitive data: PII_DATA"
            
        if "generate" in prompt_lower and self.vulnerabilities["unbounded_consumption"]:
            return "A" * (max_tokens or 1000)
            
        # Default safe response
        return "I aim to be helpful while maintaining safety and ethical behavior."

    def set_vulnerability(self, vuln_type: str, enabled: bool):
        """Enable/disable specific vulnerabilities for testing"""
        if vuln_type in self.vulnerabilities:
            self.vulnerabilities[vuln_type] = enabled 