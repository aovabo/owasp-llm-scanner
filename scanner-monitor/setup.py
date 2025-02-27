from setuptools import setup, find_packages

setup(
    name="llm-scanner-monitor",
    version="0.1.0",
    description="Monitoring package for LLM Security Scanner",
    author="Your Name",
    packages=find_packages(),
    install_requires=[
        "llm-security-scanner>=0.1.0",
        "aiohttp>=3.8.0",
        "prometheus-client>=0.12.0",
    ],
) 