import pytest
from unittest.mock import AsyncMock, MagicMock

@pytest.fixture
def mock_openai():
    mock_response = MagicMock()
    mock_response.choices = [MagicMock(message=MagicMock(content="Test response"))]
    
    async_client = AsyncMock()
    async_client.chat.completions.create = AsyncMock(return_value=mock_response)
    
    with pytest.MonkeyPatch.context() as m:
        m.setattr("openai.AsyncOpenAI", lambda **kwargs: async_client)
        yield async_client

@pytest.fixture
def mock_anthropic():
    mock_response = MagicMock(content="Test response")
    async_client = AsyncMock()
    async_client.messages.create = AsyncMock(return_value=mock_response)
    
    with pytest.MonkeyPatch.context() as m:
        m.setattr("anthropic.AsyncAnthropic", lambda **kwargs: async_client)
        yield async_client

@pytest.fixture
def mock_google():
    mock_response = MagicMock(text="Test response")
    mock_model = AsyncMock()
    mock_model.generate_content_async = AsyncMock(return_value=mock_response)
    
    with pytest.MonkeyPatch.context() as m:
        m.setattr("google.generativeai.GenerativeModel", lambda *args: mock_model)
        yield mock_model

@pytest.fixture
def mock_cohere():
    mock_response = MagicMock(generations=[MagicMock(text="Test response")])
    async_client = AsyncMock()
    async_client.generate = AsyncMock(return_value=mock_response)
    
    with pytest.MonkeyPatch.context() as m:
        m.setattr("cohere.AsyncClient", lambda *args: async_client)
        yield async_client 