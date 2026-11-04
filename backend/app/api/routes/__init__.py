"""API route registrations."""

from fastapi import APIRouter
from backend.app.api.routes.findings import router as findings_router
from backend.app.api.routes.health import router as health_router
from backend.app.api.routes.scans import router as scans_router

api_router = APIRouter()
api_router.include_router(health_router)
api_router.include_router(scans_router)
api_router.include_router(findings_router)

__all__ = ["api_router"]
