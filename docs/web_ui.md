# Web UI Documentation

## Overview
The LLM Security Scanner Web UI provides a user-friendly interface for running security scans, viewing reports, and managing continuous monitoring.

## Deployment Options

### Vercel Deployment
1. Prerequisites:
   - GitHub account
   - Vercel account
   - PostgreSQL database (e.g., Supabase, Railway)

2. Deployment Steps:
   - Fork repository
   - Connect to Vercel
   - Configure environment variables
   - Deploy

3. Environment Variables:
   ```
   DATABASE_URL=postgresql://...
   SECRET_KEY=your_secret_key
   OPENAI_API_KEY=sk-...
   ANTHROPIC_API_KEY=sk-...
   IS_WEB_UI=true
   DEPLOYMENT_ENV=vercel
   ```

### Local Development
1. Setup:
   ```bash
   git clone https://github.com/yourusername/llm-security-scanner
   cd llm-security-scanner
   pip install -r requirements.txt
   ```

2. Environment:
   ```bash
   # Create .env file
   cp .env.example .env
   # Edit .env with your values
   ```

3. Start Services:
   ```bash
   # Start API
   uvicorn scanner.ui.api:app --reload --port 8000

   # Start UI
   streamlit run scanner.ui.streamlit_app.py
   ```

## Features

### Dashboard
- Scan overview
- Recent vulnerabilities
- Security metrics
- Activity logs

### Scan Configuration
- Provider selection
- Model selection
- Vulnerability selection
- Custom parameters

### Reports
- HTML/PDF export
- Vulnerability details
- Remediation suggestions
- Historical comparison

### User Management
- Role-based access
- Team management
- API key management

### Monitoring
- Continuous scanning
- Alert configuration
- Metric tracking

## API Endpoints

### Authentication
```
POST /api/auth/login
POST /api/auth/refresh
```

### Scanning
```
POST /api/scan
GET /api/scan/{scan_id}
GET /api/scan/results/{scan_id}
```

### Reports
```
GET /api/reports
POST /api/reports/generate
```

### Users
```
GET /api/users
POST /api/users
PUT /api/users/{user_id}
```

## Troubleshooting

### Common Issues
1. Database Connection
   ```
   Error: could not connect to database
   Solution: Check DATABASE_URL format and credentials
   ```

2. API Keys
   ```
   Error: invalid API key
   Solution: Verify provider API keys in environment variables
   ```

3. CORS Issues
   ```
   Error: CORS policy blocked request
   Solution: Add domain to CORS allowed origins
   ```

### Support
- GitHub Issues
- Documentation
- Community Discord

## Security Considerations
1. API Key Storage
2. Authentication
3. Rate Limiting
4. Data Privacy 