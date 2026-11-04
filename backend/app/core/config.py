"""Configuration settings for SecurePy backend."""

from pydantic import BaseModel


class Settings(BaseModel):
    PROJECT_NAME: str = "SecurePy API"
    VERSION: str = "0.1.0"
    API_V1_PREFIX: str = "/api"
    BACKEND_CORS_ORIGINS: list[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]


settings = Settings()
