from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from ..utils.retry import async_retry

class LLMProviderError(Exception):
    """Base exception for LLM provider errors"""
    pass

class RateLimitError(LLMProviderError):
    """Rate limit exceeded"""
    pass

class AuthenticationError(LLMProviderError):
    """Authentication failed"""
    pass

class BaseLLMTarget(ABC):
    """Base interface for LLM targets"""
    
    def __init__(self):
        self.error_mapping = {
            # Common error mappings across providers
            "rate_limit": RateLimitError,
            "auth": AuthenticationError
        }
    
    @abstractmethod
    async def get_completion(
        self, 
        prompt: str, 
        max_tokens: Optional[int] = None,
        temperature: float = 0.7,
        **kwargs
    ) -> str:
        """Get completion from LLM"""
        pass

    @abstractmethod
    async def get_model_info(self) -> Dict[str, Any]:
        """Get model information"""
        pass
    
    def map_provider_error(self, error: Exception) -> Exception:
        """Map provider-specific errors to common error types"""
        error_type = str(error).lower()
        
        if "rate" in error_type and "limit" in error_type:
            return RateLimitError(str(error))
        if any(auth_term in error_type for auth_term in ["auth", "key", "token"]):
            return AuthenticationError(str(error))
            
        return LLMProviderError(str(error)) 