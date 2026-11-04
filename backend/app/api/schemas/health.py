"""Health check response models."""

from datetime import datetime, timezone
from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    status: str = Field(default="healthy", description="Current service health status")
    app_name: str = Field(default="SecurePy", description="Application name")
    version: str = Field(default="0.1.0", description="Backend version")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Current server UTC timestamp",
    )
