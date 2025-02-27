# Base image
FROM python:3.10-slim

# Set working directory
WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install -r requirements.txt

# Copy application
COPY . .
RUN pip install -e .

# Expose ports
EXPOSE 8000 8501

# Start servers
CMD ["python", "-m", "scanner.ui.run_servers"] 