from typing import Dict, Any
import anthropic
from .base_target import BaseLLMTarget
from ..utils.retry import async_retry

class AnthropicTarget(BaseLLMTarget):
    """Anthropic Claude API target"""
    
    def __init__(
        self, 
        api_key: str, 
        model: str = "claude-2"
    ):
        self.client = anthropic.AsyncAnthropic(api_key=api_key)
        self.model = model

    @async_retry(retries=3)
    async def get_completion(
        self,
        prompt: str,
        max_tokens: int = None,
        temperature: float = 0.7,
        **kwargs
    ) -> str:
        response = await self.client.messages.create(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=max_tokens,
            temperature=temperature,
            **kwargs
        )
        return response.content

    async def get_model_info(self) -> Dict[str, Any]:
        return {
            "provider": "anthropic",
            "model": self.model,
            "capabilities": {
                "max_tokens": 100000,
                "supports_functions": True
            }
        } 