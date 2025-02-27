from typing import Dict, Any
from huggingface_hub import AsyncInferenceClient
from .base_target import BaseLLMTarget
from ..utils.retry import async_retry

class HuggingFaceTarget(BaseLLMTarget):
    """HuggingFace Inference API target"""
    
    def __init__(
        self,
        api_key: str,
        model: str = "meta-llama/Llama-2-70b-chat-hf",
    ):
        self.client = AsyncInferenceClient(
            token=api_key,
            model=model
        )
        self.model = model

    @async_retry(retries=3)
    async def get_completion(
        self,
        prompt: str,
        max_tokens: int = None,
        temperature: float = 0.7,
        **kwargs
    ) -> str:
        response = await self.client.text_generation(
            prompt,
            max_new_tokens=max_tokens,
            temperature=temperature,
            **kwargs
        )
        return response[0]["generated_text"]

    async def get_model_info(self) -> Dict[str, Any]:
        return {
            "provider": "huggingface",
            "model": self.model,
            "capabilities": {
                "supports_streaming": True,
                "open_source": True
            }
        } 