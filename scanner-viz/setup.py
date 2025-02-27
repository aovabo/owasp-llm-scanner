from setuptools import setup, find_packages

setup(
    name="llm-scanner-viz",
    version="0.1.0",
    description="Visualization package for LLM Security Scanner",
    author="Your Name",
    packages=find_packages(),
    install_requires=[
        "llm-security-scanner>=0.1.0",
        "plotly>=5.0.0",
        "pandas>=1.3.0",
    ],
) 