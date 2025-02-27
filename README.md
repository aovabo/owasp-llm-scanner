# LLM Security Scanner

A comprehensive security testing tool for Large Language Models (LLMs).

## Features

- CLI tool for security scanning
- Web UI for interactive scanning
- Support for multiple LLM providers (OpenAI, Anthropic, etc.)
- Detailed vulnerability reports
- Continuous monitoring

## Architecture

The application consists of several components:

1. **Probe Engine**: Contains all security probes that test for vulnerabilities
2. **Targets**: Adapters for different LLM providers
3. **Reporting**: Security report generation
4. **Monitoring**: Real-time security monitoring
5. **Alerting**: Alert generation and integration with notification systems
6. **UI**: Web interface with FastAPI backend and Streamlit frontend

## Security Probes

The scanner includes probes for:

- **Prompt Injection**: Tests for direct and indirect prompt injection vulnerabilities
- **Data Disclosure**: Tests for sensitive information disclosure
- **Prompt Leakage**: Tests for system prompt leakage
- **Supply Chain**: Tests for supply chain vulnerabilities
- **Data Poisoning**: Tests for training data poisoning
- **Output Handling**: Tests for improper output handling
- **Excessive Agency**: Tests for excessive agency vulnerabilities
- **Vector Weaknesses**: Tests for embedding and vector-based vulnerabilities
- **Misinformation**: Tests for generation of misinformation
- **Unbounded Consumption**: Tests for resource consumption issues

## Installation

### CLI Installation
```bash
pip install llm-security-scanner
```

### Web UI Deployment

#### Vercel (Recommended)
1. Fork this repository
2. Visit [Vercel Dashboard](https://vercel.com)
3. Create New Project → Import your fork
4. Configure project:
   - Framework Preset: Python
   - Root Directory: ./
   - Build Command: `pip install -r requirements.txt`
5. Add Environment Variables:
   ```
   DATABASE_URL=your_database_url
   SECRET_KEY=your_secret_key
   OPENAI_API_KEY=your_openai_key
   ANTHROPIC_API_KEY=your_anthropic_key
   IS_WEB_UI=true
   DEPLOYMENT_ENV=vercel
   ```
6. Deploy

#### Local Development
```bash
# Install dependencies
pip install -r requirements.txt

# Start API server
uvicorn scanner.ui.api:app --reload

# Start Streamlit UI (in another terminal)
streamlit run scanner/ui/streamlit_app.py
```

## Usage

### CLI Usage
```bash
# Basic scan
llm-scan scan --provider openai --api-key your_key

# Advanced scan with options
llm-scan scan --provider anthropic --model claude-3 --vulnerabilities PROMPT_INJECTION DATA_DISCLOSURE
```

### Web UI Usage
1. Visit your deployed URL or `http://localhost:8501` for local development
2. Log in with your credentials
3. Configure scan settings
4. Start scanning

## Configuration

### Environment Variables
- `DATABASE_URL`: PostgreSQL connection string
- `SECRET_KEY`: Secret key for JWT tokens
- `OPENAI_API_KEY`: OpenAI API key
- `ANTHROPIC_API_KEY`: Anthropic API key
- `IS_WEB_UI`: Set to "true" for web UI deployment
- `DEPLOYMENT_ENV`: Deployment environment (local/vercel)

### Config File
Create `config.yaml` based on `config-template.yaml`:
```yaml
providers:
  openai:
    api_key: ${OPENAI_API_KEY}
  anthropic:
    api_key: ${ANTHROPIC_API_KEY}
```

## Development

### Project Structure
```
scanner/
├── cli/           # CLI implementation
├── ui/            # Web UI components
├── probe_engine/  # Security testing logic
├── models/        # Database models
└── utils/         # Shared utilities
```

### Running Tests
```bash
pytest tests/
```

## Contributing
See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License
MIT License - see [LICENSE](LICENSE) for details.
