"""Database Session Dependency for FastAPI."""

from typing import Iterator
import sqlite3
from backend.app.database.db import get_connection


def get_db() -> Iterator[sqlite3.Connection]:
    """Yield an open SQLite connection and ensure clean closure."""
    conn = get_connection()
    try:
        yield conn
    finally:
        conn.close()
