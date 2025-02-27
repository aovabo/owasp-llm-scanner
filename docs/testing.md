# Testing Guide: LLM Security Scanner

This document provides comprehensive instructions for testing the LLM Security Scanner application.

## 1. Setup Environment

### Version Compatibility

This project uses the following major package versions with potential breaking changes:

- FastAPI >= 0.110.0: New response validation and dependency system
- Streamlit >= 1.31.1: Updated session state and layout system
- Pandas >= 2.2.1: New DataFrame operations and type system
- Anthropic >= 0.18.1: Updated API client and response formats

If you encounter issues, check the specific package's migration guide:
- [FastAPI Migration Guide](https://fastapi.tiangolo.com/release-notes/)
- [Streamlit Changelog](https://docs.streamlit.io/library/changelog)
- [Pandas Whatsnew](https://pandas.pydata.org/docs/whatsnew/index.html)
- [Anthropic Python SDK](https://github.com/anthropics/anthropic-sdk-python/releases)

```bash
# Clone the repository (if not already done)
git clone https://github.com/yourusername/llm-security-scanner.git
cd llm-security-scanner

# Install dependencies
pip install -r requirements.txt

# Create a .env file for configuration
touch .env
```

Add the following to your `.env` file:

```
# API Keys for LLM Providers
OPENAI_API_KEY=your_openai_key
ANTHROPIC_API_KEY=your_anthropic_key

# Authentication Providers (for Web UI)
GITHUB_CLIENT_ID=your_github_client_id
GITHUB_CLIENT_SECRET=your_github_client_secret
SECRET_KEY=your_secret_key_for_jwt

# Alerting Config (optional)
SLACK_WEBHOOK_URL=your_slack_webhook_url
ALERT_EMAIL=your_email@example.com
```

## 2. Testing Package Functionality

### CLI Testing

```bash
# Test basic CLI functionality
llm-scan --help

# Test scanning
llm-scan --provider openai --model gpt-4 --api-key your_api_key

# Test report generation
llm-scan --output report.html
```

### Python API Testing

```python
from scanner.probe_engine import ProbeEngine
from scanner.targets import create_target

# Test basic scanning
target = create_target("openai:gpt-4", api_key="your_api_key")
engine = ProbeEngine()
results = await engine.run_scan(target)

# Test specific vulnerabilities
engine = ProbeEngine(enabled_vulnerabilities=["PROMPT_INJECTION"])
results = await engine.run_scan(target)
```

## 3. Testing Web UI

### Start the servers

```bash
# Start both the FastAPI backend and Streamlit frontend
python -m scanner.ui.run_servers
```

This will start:
- FastAPI backend on port 8000
- Streamlit frontend on port 8501

### Access the UI

Open your browser and navigate to:
- http://localhost:8501 for the Streamlit UI

### Testing Flow:

1. **Authentication**
   - Click "Login with GitHub"
   - Complete the OAuth flow
   - You should be redirected back to the application

2. **Running a Scan**
   - Select a provider from the dropdown
   - Enter your API key
   - Select vulnerabilities to test
   - Click "Start Scan"
   - Watch the progress updates in real-time
   - View the final report with visualizations

3. **Configuration Management**
   - Save your current configuration
   - Load a previously saved configuration
   - Start a new scan with the loaded configuration

4. **User Management** (admin only)
   - Go to the User Management section
   - Create a new user
   - Assign roles
   - View user list

5. **Audit Reports** (admin only)
   - Go to the Audit section
   - Generate a new audit report
   - Filter by date range or users
   - Export the report

## 4. Testing API Endpoints

Test the API endpoints using tools like `curl` or Postman:

```bash
# Get API status
curl http://localhost:8000/status

# Run a scan (requires authentication)
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -H "Cookie: access_token=your_jwt_token" \
  -d '{"target_url": "openai:gpt-4", "api_key": "your_api_key"}'

# Get scan results
curl http://localhost:8000/scan/scan_123
```

## 5. Testing Authentication

If you don't want to set up OAuth providers, you can modify the `scanner/ui/auth.py` file to add a test user:

```python
# Add this to scanner/ui/auth.py
users = {
    "test_user": User(
        id="test_user",
        email="test@example.com",
        name="Test User",
        provider="test",
        role=UserRole.ADMIN
    )
}
```

## 6. Unit Testing

Run the test suite to validate core components:

```bash
# Run all tests
pytest

# Run specific test categories
pytest tests/test_probe_engine/
pytest tests/test_ui/

# Run with coverage report
pytest --cov=scanner tests/
```

## 7. Debugging Tips

If you encounter issues:

1. **Web UI Issues**
   - Check both terminal windows for error messages
   - Verify authentication configuration
   - Check browser console for frontend errors

2. **Probe Engine Issues**
   - Verify API keys are valid
   - Check target configuration
   - Enable debug logging

3. **Authentication Issues**
   - Verify OAuth configuration
   - Check cookie settings
   - Validate JWT token configuration

## 8. Common Test Scenarios

1. **Basic Scan Test**
```python
# Test basic scan functionality
from scanner.probe_engine.probe_engine import ProbeEngine
engine = ProbeEngine()
results = await engine.run_scan(target)
```

2. **User Management Test**
```python
# Test user management
from scanner.ui.user_management import UserManager
user_manager = UserManager()
user = user_manager.create_user(user_data)
```

3. **Audit Logging Test**
```python
# Test audit logging
from scanner.ui.audit import AuditLogger
logger = AuditLogger()
await logger.log_action(user, "test_action", "test_resource")
```

## 9. Error Cases

Test common error scenarios:

1. Invalid API keys
2. Authentication failures
3. Missing configurations
4. Network failures
5. Invalid scan parameters

## 10. Reporting Issues

When reporting issues:

1. Include full test scenario
2. Attach relevant logs
3. Provide configuration used
4. Describe expected vs actual behavior
5. Include system information 

## CLI Usage Examples

### Basic Scanning

```bash
# Run a basic scan
llm-scan scan --provider openai --model gpt-4 --api-key your_api_key

# Run scan with specific vulnerabilities
llm-scan scan --provider openai --vulnerabilities PROMPT_INJECTION DATA_DISCLOSURE

# Run scan with additional options
llm-scan scan --provider openai --api-key your_key --timeout 600 --max-retries 5 --verbose

# Run scan with advanced options
llm-scan scan --provider openai --parallel --risk-threshold 5 --format json

# Run scan without progress bar
llm-scan scan --provider openai --no-progress --save-artifacts
```

### Vulnerability Analysis

```bash
# Analyze last scan
llm-scan analyze --trend

# Analyze specific vulnerability type
llm-scan analyze --vulnerability-type PROMPT_INJECTION --severity HIGH

# Compare two scans
llm-scan analyze --scan-id scan_123 --compare scan_456

# Save analysis to file
llm-scan analyze --scan-id scan_123 --output analysis.json
```

### Report Generation

```bash
# Generate HTML report for last scan
llm-scan report --last --format html --output latest_scan.html

# Generate full report with evidence
llm-scan report --scan-id scan_123 --format pdf --full

# Generate summary report
llm-scan report --last --summary --format markdown
```

### Configuration Management

```bash
# Initialize new config
llm-scan config --init --output my_config.yaml

# Validate existing config
llm-scan validate --config my_config.yaml
```

### Information Commands

```bash
# List all available probes
llm-scan info --list-probes

# List supported providers and models
llm-scan info --list-providers
```

### Continuous Monitoring

```bash
# Start continuous monitoring
llm-scan monitor --continuous --interval 1800 --alert-threshold HIGH
``` 