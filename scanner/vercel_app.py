from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .ui.api import app as api_app
from .ui.streamlit_app import main as streamlit_app
import os

# Create Vercel-specific FastAPI app
app = FastAPI(title="LLM Scanner Web UI")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Update this for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount the API
app.mount("/api", api_app)

# Health check endpoint
@app.get("/health")
async def health_check():
    return {"status": "healthy"}

# Export for Vercel
handler = app 