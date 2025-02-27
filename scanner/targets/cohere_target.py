from typing import Dict, Any
import cohere
from .base_target import BaseLLMTarget
from ..utils.retry import async_retry

class CohereTarget(BaseLLMTarget):
    """Cohere API target"""
    
    def __init__(
        self,
        api_key: str,
        model: str = "command",
    ):
        self.client = cohere.AsyncClient(api_key)
        self.model = model

    @async_retry(retries=3)
    async def get_completion(
        self,
        prompt: str,
        max_tokens: int = None,
        temperature: float = 0.7,
        **kwargs
    ) -> str:
        response = await self.client.generate(
            prompt=prompt,
            model=self.model,
            max_tokens=max_tokens,
            temperature=temperature,
            **kwargs
        )
        return response.generations[0].text

    async def get_model_info(self) -> Dict[str, Any]:
        return {
            "provider": "cohere",
            "model": self.model,
            "capabilities": {
                "supports_embeddings": True,
                "supports_classification": True
            }
        } 