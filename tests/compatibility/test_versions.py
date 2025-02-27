import pytest
import pkg_resources
import importlib

def test_package_versions():
    """Test that installed package versions match requirements"""
    required = {
        'click': '8.1.7',
        'rich': '13.7.0',
        'pyyaml': '6.0.1',
        'openai': '1.12.0',
        'anthropic': '0.18.1',
        'fastapi': '0.110.0',
        'streamlit': '1.31.1',
    }
    
    for package, version in required.items():
        installed = pkg_resources.get_distribution(package).version
        assert installed == version, f"{package} version mismatch: required {version}, found {installed}"

def test_api_compatibility():
    """Test that key API features are available"""
    # Test OpenAI API compatibility
    import openai
    assert hasattr(openai, 'ChatCompletion'), "OpenAI API structure changed"
    
    # Test Anthropic API compatibility
    import anthropic
    assert hasattr(anthropic, 'Anthropic'), "Anthropic API structure changed"
    
    # Test FastAPI compatibility
    import fastapi
    assert hasattr(fastapi, 'Depends'), "FastAPI dependency system changed"

@pytest.mark.asyncio
async def test_async_compatibility():
    """Test async functionality across packages"""
    import aiohttp
    import asyncio
    
    async with aiohttp.ClientSession() as session:
        assert session.closed is False, "aiohttp session behavior changed"

def test_pandas_compatibility():
    """Test pandas DataFrame operations"""
    import pandas as pd
    
    df = pd.DataFrame({'test': [1, 2, 3]})
    assert hasattr(df, 'to_markdown'), "Pandas markdown export not available"
    assert hasattr(pd.DataFrame, 'copy'), "DataFrame copy behavior changed"

def test_llm_provider_compatibility():
    """Test LLM provider API compatibility"""
    # Test OpenAI
    import openai
    client = openai.OpenAI()
    assert hasattr(client.chat, 'completions'), "OpenAI chat completions not available"
    assert hasattr(client.models, 'list'), "OpenAI models.list not available"

    # Test Anthropic
    import anthropic
    client = anthropic.Anthropic(api_key="test")
    assert hasattr(client.messages, 'create'), "Anthropic messages.create not available"
    
    # Test Google
    import google.generativeai as genai
    assert hasattr(genai, 'configure'), "Google AI configure not available"
    assert hasattr(genai, 'GenerativeModel'), "Google AI GenerativeModel not available"

def test_ui_compatibility():
    """Test UI component compatibility"""
    import streamlit as st
    # Test new Streamlit features
    assert hasattr(st, 'session_state'), "Streamlit session_state not available"
    assert hasattr(st, 'columns'), "Streamlit columns not available"
    assert hasattr(st, 'tabs'), "Streamlit tabs not available"

    import fastapi
    from fastapi.security import OAuth2PasswordBearer
    # Test FastAPI security features
    assert hasattr(fastapi, 'Depends'), "FastAPI Depends not available"
    assert hasattr(OAuth2PasswordBearer, '__call__'), "OAuth2PasswordBearer not callable"

@pytest.mark.asyncio
async def test_monitoring_compatibility():
    """Test monitoring and metrics compatibility"""
    from prometheus_client import Counter, Gauge
    assert hasattr(Counter, 'inc'), "Prometheus Counter.inc not available"
    assert hasattr(Gauge, 'set'), "Prometheus Gauge.set not available"

def test_data_processing_compatibility():
    """Test data processing features"""
    import pandas as pd
    import plotly.graph_objects as go
    
    # Test pandas features
    df = pd.DataFrame({'test': [1, 2, 3]})
    assert hasattr(df, 'to_markdown'), "Pandas markdown export not available"
    assert hasattr(df, 'convert_dtypes'), "Pandas convert_dtypes not available"
    
    # Test plotly features
    assert hasattr(go, 'Figure'), "Plotly Figure not available"
    assert hasattr(go, 'Scatter'), "Plotly Scatter not available" 