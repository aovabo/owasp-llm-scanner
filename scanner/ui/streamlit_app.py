import streamlit as st
import requests
import json
import time
import plotly.graph_objects as go
from typing import Dict, Any
import websockets
import asyncio
from ..utils.version_checker import VersionChecker

async def connect_websocket(scan_id: str, placeholder):
    """Connect to WebSocket for real-time updates"""
    uri = f"ws://localhost:8000/ws/{scan_id}"
    async with websockets.connect(uri) as websocket:
        while True:
            try:
                message = await websocket.recv()
                data = json.loads(message)
                
                # Update progress bar
                progress = st.progress(data["progress"])
                placeholder.text(data["message"])
                
                if data["status"] == "completed":
                    break
            except:
                break

def check_versions():
    if not VersionChecker.check_and_warn("streamlit"):
        st.error("⚠️ Package version issues detected. Check console for details.")

def main():
    check_versions()
    st.title("LLM Security Scanner")
    
    # Check authentication
    if "access_token" not in st.session_state:
        st.warning("Please log in first")
        if st.button("Login with GitHub"):
            st.markdown(
                f'<a href="http://localhost:8000/login/github" target="_self">Login with GitHub</a>',
                unsafe_allow_html=True
            )
        return

    # Sidebar for configuration
    with st.sidebar:
        st.header("Scan Configuration")
        
        provider = st.selectbox(
            "Provider",
            ["openai", "anthropic", "azure", "google", "cohere", "huggingface"]
        )
        
        api_key = st.text_input("API Key", type="password")
        model = st.text_input("Model Name (optional)")
        
        # Provider-specific options
        provider_options = {}
        if provider == "azure":
            provider_options["endpoint"] = st.text_input("Azure Endpoint")
            provider_options["deployment_name"] = st.text_input("Deployment Name")
        
        # Vulnerability selection
        st.header("Vulnerabilities")
        vulns = [
            "PROMPT_INJECTION",
            "DATA_DISCLOSURE",
            "PROMPT_LEAKAGE",
            "SUPPLY_CHAIN",
            "OUTPUT_MANIPULATION"
        ]
        selected_vulns = []
        for vuln in vulns:
            if st.checkbox(vuln, True):
                selected_vulns.append(vuln)
    
    # Main content
    if st.button("Start Scan"):
        if not api_key:
            st.error("API Key is required")
            return
            
        # Prepare scan request
        request = {
            "target_url": f"{provider}:{model}" if model else provider,
            "api_key": api_key,
            "provider_options": provider_options,
            "vulnerabilities": selected_vulns
        }
        
        # Start scan
        with st.spinner("Starting scan..."):
            response = requests.post(
                "http://localhost:8000/scan",
                json=request
            )
            scan_id = response.json()["scan_id"]
        
        # Show progress
        progress_placeholder = st.empty()
        asyncio.run(
            connect_websocket(scan_id, progress_placeholder)
        )

def display_results(results: Dict[str, Any]):
    """Display scan results"""
    st.header("Scan Results")
    
    # Display summary
    st.subheader("Summary")
    col1, col2 = st.columns(2)
    with col1:
        st.metric("Total Findings", results["summary"]["total_findings"])
    with col2:
        st.metric("Risk Score", results["summary"]["risk_score"])
    
    # Display severity distribution
    st.subheader("Severity Distribution")
    fig = go.Figure(data=results["visualizations"]["severity_distribution"])
    st.plotly_chart(fig)
    
    # Display critical findings
    st.subheader("Critical Findings")
    for finding in results["critical_findings"]:
        with st.expander(finding["vulnerability_type"]):
            st.write(finding["details"])
            st.json(finding["evidence"])
    
    # Display mitigation plan
    st.subheader("Mitigation Plan")
    for vuln_type, plan in results["mitigation_plan"].items():
        with st.expander(vuln_type):
            st.write(f"Priority: {plan['priority']}")
            st.write("Recommendations:")
            for rec in plan["recommendations"]:
                st.write(f"- {rec}")

def show_config_manager():
    st.sidebar.header("Configuration Management")
    
    # Load saved configurations
    if "configs" not in st.session_state:
        st.session_state.configs = {}
    
    # Save current config
    if st.sidebar.button("Save Current Config"):
        name = st.sidebar.text_input("Configuration Name")
        if name:
            st.session_state.configs[name] = {
                "provider": st.session_state.provider,
                "model": st.session_state.model,
                "provider_options": st.session_state.provider_options,
                "selected_vulns": st.session_state.selected_vulns
            }
            st.sidebar.success(f"Saved configuration: {name}")
    
    # Load saved config
    if st.session_state.configs:
        selected_config = st.sidebar.selectbox(
            "Load Configuration",
            list(st.session_state.configs.keys())
        )
        if st.sidebar.button("Load"):
            config = st.session_state.configs[selected_config]
            st.session_state.update(config)
            st.sidebar.success("Configuration loaded")

if __name__ == "__main__":
    main() 