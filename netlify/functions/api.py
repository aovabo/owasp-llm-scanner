from http.server import BaseHTTPRequestHandler
from scanner.ui.api import app
import json
from mangum import Mangum

# Create handler for AWS Lambda
handler = Mangum(app)

def handle(event, context):
    """Handle incoming serverless requests"""
    return handler(event, context) 