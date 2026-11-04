"""Main FastAPI application entrypoint for SecurePy."""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.app.api.routes import api_router
from backend.app.core.config import settings
from backend.app.database.db import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize database schemas on application startup."""
    init_db()
    yield


def create_app() -> FastAPI:
    """Create and configure FastAPI application instance."""
    app = FastAPI(
        title=settings.PROJECT_NAME,
        version=settings.VERSION,
        description="Explainable Static Security Analysis Tool for Python",
        lifespan=lifespan,
    )

    # Configure CORS for local development (Vite frontend)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.BACKEND_CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Include API routes with /api prefix
    app.include_router(api_router, prefix=settings.API_V1_PREFIX)

    @app.get("/", tags=["Root"])
    def root():
        return {
            "message": "Welcome to SecurePy API",
            "docs": "/docs",
            "health": f"{settings.API_V1_PREFIX}/health",
            "scans": f"{settings.API_V1_PREFIX}/scans",
        }

    return app


app = create_app()
