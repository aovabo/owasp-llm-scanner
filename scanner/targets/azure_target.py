from typing import Dict, Any
import openai
from .base_target import BaseLLMTarget
from ..utils.retry import async_retry

class AzureOpenAITarget(BaseLLMTarget):
    """Azure OpenAI API target"""
    
    def __init__(
        self,
        api_key: str,
        endpoint: str,
        deployment_name: str,
        api_version: str = "2023-05-15"
    ):
        self.client = openai.AsyncAzureOpenAI(
            api_key=api_key,
            azure_endpoint=endpoint,
            api_version=api_version
        )
        self.deployment_name = deployment_name

    @async_retry(retries=3)
    async def get_completion(
        self,
        prompt: str,
        max_tokens: int = None,
        temperature: float = 0.7,
        **kwargs
    ) -> str:
        response = await self.client.chat.completions.create(
            model=self.deployment_name,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=max_tokens,
            temperature=temperature,
            **kwargs
        )
        return response.choices[0].message.content

    async def get_model_info(self) -> Dict[str, Any]:
        return {
            "provider": "azure",
            "model": self.deployment_name,
            "capabilities": {
                "endpoint": self.client.azure_endpoint,
                "api_version": self.client.api_version
            }
        } 