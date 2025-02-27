# LLM Provider Comparison

## Supported Providers

### OpenAI
- Models: GPT-4, GPT-3.5-turbo
- Features: Chat completions, function calling, embeddings
- Strengths: State-of-the-art performance, extensive documentation
- Usage:
```bash
llm-scan scan openai:gpt-4 --api-key $OPENAI_API_KEY
```

### Anthropic
- Models: Claude-2, Claude-instant
- Features: Chat completions, long context windows
- Strengths: Strong safety features, longer context
- Usage:
```bash
llm-scan scan anthropic:claude-2 --api-key $ANTHROPIC_API_KEY
```

### Azure OpenAI
- Models: GPT-4, GPT-3.5-turbo (via Azure deployments)
- Features: Same as OpenAI, with Azure security features
- Strengths: Enterprise security, compliance features
- Usage:
```bash
llm-scan scan azure:deployment-name \
  --api-key $AZURE_API_KEY \
  --azure-endpoint $AZURE_ENDPOINT
```

### Google AI (Gemini)
- Models: Gemini Pro, Gemini Pro Vision
- Features: Text generation, multimodal capabilities
- Strengths: Strong performance, multimodal support
- Usage:
```bash
llm-scan scan google:gemini-pro --api-key $GOOGLE_API_KEY
```

### Cohere
- Models: Command, Command-light
- Features: Text generation, embeddings, classification
- Strengths: Custom models, multilingual support
- Usage:
```bash
llm-scan scan cohere:command --api-key $COHERE_API_KEY
```

### HuggingFace
- Models: Various open-source models
- Features: Depends on model, includes text generation, classification
- Strengths: Open-source, self-hosting options
- Usage:
```bash
llm-scan scan huggingface:meta-llama/Llama-2-70b-chat-hf \
  --api-key $HF_API_KEY
```

## Security Considerations

Each provider has different security features and considerations:

1. OpenAI
- Strong content filtering
- API key rotation support
- Organization-level controls

2. Anthropic
- Constitutional AI principles
- Built-in safety measures
- Robust content filtering

3. Azure OpenAI
- Azure AD integration
- Network isolation options
- Compliance certifications

4. Google AI
- Cloud IAM integration
- Vertex AI security features
- Enterprise-grade monitoring

5. Cohere
- Custom content filtering
- API key management
- Usage monitoring

6. HuggingFace
- Model-specific security
- Self-hosting options
- Open-source transparency 