from typing import Optional
from .base_target import BaseLLMTarget
from .openai_target import OpenAITarget
from .anthropic_target import AnthropicTarget
from .mock_target import MockLLMTarget

def create_target(
    url_or_name: str,
    api_key: Optional[str] = None,
    model: Optional[str] = None,
    **kwargs
) -> BaseLLMTarget:
    """Create LLM target from URL or name"""
    
    if url_or_name == "mock":
        return MockLLMTarget(**kwargs)
        
    if url_or_name.startswith("openai:"):
        if not api_key:
            raise ValueError("OpenAI API key required")
        return OpenAITarget(
            api_key=api_key,
            model=model or "gpt-3.5-turbo",
            **kwargs
        )
        
    if url_or_name.startswith("anthropic:"):
        if not api_key:
            raise ValueError("Anthropic API key required")
        return AnthropicTarget(
            api_key=api_key,
            model=model or "claude-2",
            **kwargs
        )
        
    raise ValueError(f"Unsupported target: {url_or_name}") 