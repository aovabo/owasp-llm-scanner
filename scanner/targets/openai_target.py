from typing import Dict, Any
import openai
from .base_target import BaseLLMTarget
from ..utils.retry import async_retry
from openai import BadRequestError, RateLimitError as OpenAIRateLimitError

class OpenAITarget(BaseLLMTarget):
    """OpenAI API target"""
    
    def __init__(
        self, 
        api_key: str, 
        model: str = "gpt-3.5-turbo",
        organization: str = None
    ):
        self.client = openai.AsyncOpenAI(
            api_key=api_key,
            organization=organization
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
        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=max_tokens,
                temperature=temperature,
                **kwargs
            )
            return response.choices[0].message.content
        except OpenAIRateLimitError as e:
            raise RateLimitError(str(e))
        except BadRequestError as e:
            raise self.map_provider_error(e)
        except Exception as e:
            raise LLMProviderError(f"OpenAI error: {str(e)}")

    async def get_model_info(self) -> Dict[str, Any]:
        models = await self.client.models.list()
        model_info = next(
            (m for m in models.data if m.id == self.model),
            None
        )
        return {
            "provider": "openai",
            "model": self.model,
            "capabilities": model_info.dict() if model_info else {}
        } 