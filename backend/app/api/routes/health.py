"""Health check endpoint route."""

from fastapi import APIRouter
from backend.app.api.schemas.health import HealthResponse

router = APIRouter()


@router.get("/health", response_model=HealthResponse, tags=["Health"])
def get_health() -> HealthResponse:
    """Return system health status."""
    return HealthResponse()
