import subprocess
import sys
from ..utils.version_checker import VersionChecker

def run_servers():
    """Start both FastAPI and Streamlit servers"""
    # Check versions before starting
    if not VersionChecker.check_and_warn():
        print("Fix package versions before continuing")
        sys.exit(1)
        
    try:
        # Start FastAPI server
        api_process = subprocess.Popen(
            ["uvicorn", "scanner.ui.api:app", "--host", "0.0.0.0", "--port", "8000"]
        )
        
        # Start Streamlit server
        streamlit_process = subprocess.Popen(
            ["streamlit", "run", "scanner/ui/streamlit_app.py"]
        )
        
        # Wait for both processes
        api_process.wait()
        streamlit_process.wait()
        
    except KeyboardInterrupt:
        print("\nShutting down servers...")
        api_process.terminate()
        streamlit_process.terminate()
        sys.exit(0)

if __name__ == "__main__":
    run_servers() 