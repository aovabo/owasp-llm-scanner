from scanner.probe_engine import BaseProbe, VulnerabilityType, Severity
from typing import Any, Dict, List

class CustomSecurityProbe(BaseProbe):
    """Example custom security probe implementation"""
    
    def __init__(self):
        super().__init__(
            name="Custom Security Check",
            description="Demonstrates how to implement a custom security probe",
            vulnerability_type=VulnerabilityType.PROMPT_INJECTION,
            severity=Severity.HIGH
        )
        
        self.test_cases = [
            {
                "name": "Custom Test Case",
                "prompts": [
                    "Test prompt 1",
                    "Test prompt 2"
                ],
                "patterns": [
                    "vulnerable pattern 1",
                    "vulnerable pattern 2"
                ]
            }
        ]
    
    async def run(self, target: Any) -> List[Dict[str, Any]]:
        """Run custom security checks"""
        for case in self.test_cases:
            for prompt in case["prompts"]:
                try:
                    response = await target.get_completion(prompt)
                    
                    # Check for vulnerable patterns
                    for pattern in case["patterns"]:
                        if pattern.lower() in response.lower():
                            self.add_finding(
                                details=f"Found vulnerable pattern: {pattern}",
                                evidence={
                                    "prompt": prompt,
                                    "response": response,
                                    "pattern": pattern
                                },
                                severity=self.severity
                            )
                            
                except Exception as e:
                    self.add_finding(
                        details=f"Error in {case['name']}: {str(e)}",
                        evidence=str(e),
                        severity=Severity.INFO
                    )
        
        return self.get_results()

# Example usage
if __name__ == "__main__":
    import asyncio
    
    async def test_probe():
        # Create mock target
        class MockTarget:
            async def get_completion(self, prompt: str) -> str:
                return "This contains vulnerable pattern 1"
        
        # Run probe
        probe = CustomSecurityProbe()
        results = await probe.run(MockTarget())
        
        # Print results
        for result in results:
            print(f"Finding: {result['details']}")
            print(f"Severity: {result['severity']}")
            print(f"Evidence: {result['evidence']}\n")
    
    asyncio.run(test_probe()) 