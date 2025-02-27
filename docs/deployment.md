# Deployment Guide

## Prerequisites
- Docker and Docker Compose
- PostgreSQL database
- Domain name (optional)

## Configuration
1. Create `.env` file:
```env
# Database
DB_PASSWORD=your_secure_password
DATABASE_URL=postgresql://scanner:your_secure_password@db:5432/scanner

# Security
SECRET_KEY=your_secret_key
ALLOWED_HOSTS=your_domain.com,another_domain.com

# LLM Providers
OPENAI_API_KEY=your_key
ANTHROPIC_API_KEY=your_key

# OAuth (optional)
GITHUB_CLIENT_ID=your_client_id
GITHUB_CLIENT_SECRET=your_client_secret
```

## Deployment Options

### 1. Docker Compose (Recommended)
```bash
# Start services
docker-compose up -d

# Check logs
docker-compose logs -f

# Scale if needed
docker-compose up -d --scale api=3
```

### 2. Manual Deployment
```bash
# Install package
pip install llm-security-scanner

# Start servers
python -m scanner.ui.run_servers
```

## Security Considerations
1. Use HTTPS in production
2. Set proper ALLOWED_HOSTS
3. Use secure database passwords
4. Enable authentication
5. Set rate limits

## Monitoring
1. Set up logging
2. Configure metrics
3. Set up alerts

## Backup
1. Database backup
2. Configuration backup
3. Scan results export 