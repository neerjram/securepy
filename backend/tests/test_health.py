"""Test health check and root endpoints."""

from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)


def test_root_endpoint():
    """Verify root endpoint responds with basic service info."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert "message" in data
    assert data["message"] == "Welcome to SecurePy API"
    assert data["health"] == "/api/health"


def test_health_check_endpoint():
    """Verify /api/health endpoint returns healthy status and metadata."""
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["app_name"] == "SecurePy"
    assert "version" in data
    assert "timestamp" in data
