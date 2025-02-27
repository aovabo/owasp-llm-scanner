import pytest
from scanner.targets import create_target
from scanner.targets.base_target import BaseLLMTarget
from scanner.targets.openai_target import OpenAITarget
from scanner.targets.anthropic_target import AnthropicTarget
from scanner.targets.azure_target import AzureOpenAITarget
from scanner.targets.google_target import GoogleAITarget

class TestTargetCreation:
    def test_create_mock_target(self):
        target = create_target("mock")
        assert isinstance(target, BaseLLMTarget)

    def test_create_openai_target(self):
        target = create_target(
            "openai:gpt-4",
            api_key="test_key",
            model="gpt-4"
        )
        assert isinstance(target, OpenAITarget)
        assert target.model == "gpt-4"

    def test_create_anthropic_target(self):
        target = create_target(
            "anthropic:claude-2",
            api_key="test_key",
            model="claude-2"
        )
        assert isinstance(target, AnthropicTarget)
        assert target.model == "claude-2"

    def test_missing_api_key(self):
        with pytest.raises(ValueError):
            create_target("openai:gpt-4")

    def test_unsupported_target(self):
        with pytest.raises(ValueError):
            create_target("unsupported:model")

@pytest.mark.asyncio
class TestTargetImplementations:
    async def test_openai_completion(self, mock_openai):
        target = OpenAITarget(api_key="test_key")
        response = await target.get_completion("Test prompt")
        assert isinstance(response, str)
        assert len(response) > 0

    async def test_anthropic_completion(self, mock_anthropic):
        target = AnthropicTarget(api_key="test_key")
        response = await target.get_completion("Test prompt")
        assert isinstance(response, str)
        assert len(response) > 0

    async def test_azure_completion(self, mock_azure):
        target = AzureOpenAITarget(
            api_key="test_key",
            endpoint="https://test.openai.azure.com",
            deployment_name="gpt-35-turbo"
        )
        response = await target.get_completion("Test prompt")
        assert isinstance(response, str)
        assert len(response) > 0

    async def test_google_completion(self, mock_google):
        target = GoogleAITarget(api_key="test_key")
        response = await target.get_completion("Test prompt")
        assert isinstance(response, str)
        assert len(response) > 0 