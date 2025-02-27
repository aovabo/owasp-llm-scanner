from typing import Dict, Any
import google.generativeai as genai
from .base_target import BaseLLMTarget
from ..utils.retry import async_retry

class GoogleAITarget(BaseLLMTarget):
    """Google AI (Gemini) API target"""
    
    def __init__(
        self,
        api_key: str,
        model: str = "gemini-pro"
    ):
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel(model)

    @async_retry(retries=3)
    async def get_completion(
        self,
        prompt: str,
        max_tokens: int = None,
        temperature: float = 0.7,
        **kwargs
    ) -> str:
        response = await self.model.generate_content_async(
            prompt,
            generation_config={
                "max_output_tokens": max_tokens,
                "temperature": temperature,
                **kwargs
            }
        )
        return response.text

    async def get_model_info(self) -> Dict[str, Any]:
        return {
            "provider": "google",
            "model": self.model.model_name,
            "capabilities": {
                "supports_functions": True,
                "supports_vision": "vision" in self.model.model_name
            }
        } 