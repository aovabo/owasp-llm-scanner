import pytest
from fastapi.testclient import TestClient
from scanner.ui.api import app
from scanner.ui.auth import User, UserRole

@pytest.fixture
def test_client():
    return TestClient(app)

@pytest.fixture
def test_user():
    return User(
        id="test_user",
        email="test@example.com",
        name="Test User",
        provider="test",
        role=UserRole.ADMIN
    )

def test_scan_endpoint(test_client, test_user):
    response = test_client.post(
        "/scan",
        json={
            "target_url": "openai:gpt-4",
            "api_key": "test_key"
        },
        cookies={"access_token": "test_token"}
    )
    assert response.status_code == 200
    assert "scan_id" in response.json()

def test_scan_results_endpoint(test_client):
    response = test_client.get("/scan/test_scan_1")
    assert response.status_code == 404  # No scan exists yet 