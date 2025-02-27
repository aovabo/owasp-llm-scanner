from setuptools import setup, find_packages

setup(
    name="llm-security-scanner",
    version="0.1.0",
    description="OWASP Top 10 LLM Security Scanner",
    author="Alexander",
    packages=find_packages(),
    install_requires=[
        # Core dependencies with strict version ranges
        "click>=8.1.7,<8.2.0",  # More strict than <9.0.0
        "rich>=13.7.0,<13.8.0",
        "pyyaml>=6.0.1,<6.1.0",
        
        # LLM Providers with tested versions
        "openai==1.12.0",  # Exact version for API compatibility
        "anthropic==0.18.1",
        "google-generativeai==0.3.2",
        "cohere==4.50",
        "huggingface-hub>=0.21.3,<0.22.0",
        
        # UI dependencies with compatible versions
        "fastapi>=0.110.0,<0.111.0",  # Strict minor version
        "streamlit>=1.31.1,<1.32.0",
        "uvicorn>=0.27.1,<0.28.0",
        "jinja2>=3.1.3,<3.2.0",
        
        # Optional dependencies
        "plotly>=5.19.0,<5.20.0",
        "pandas>=2.2.1,<2.3.0",
        "aiohttp>=3.9.3,<3.10.0",
        "prometheus-client>=0.20.0,<0.21.0",
    ],
    extras_require={
        'dev': [
            'pytest==8.0.2',
            'pytest-asyncio==0.23.5',
            'pytest-cov==4.1.0',  # Added for coverage reports
            'black==24.2.0',  # Added for formatting
            'isort==5.13.2',  # Added for import sorting
        ],
        'test': [
            'pytest-mock==3.12.0',
            'pytest-asyncio==0.23.5',
            'pytest-timeout==2.2.0',
            'responses==0.25.0',  # For mocking HTTP requests
        ],
    },
    entry_points={
        'console_scripts': [
            'llm-scan=scanner.cli.main:main',
        ],
    },
    python_requires=">=3.8,<3.12",  # Specify Python version range
)
