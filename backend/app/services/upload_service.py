"""Safe File and Archive Upload Service for SecurePy.

Enforces strict security checks on uploaded files:
- Rejects oversized archives and files.
- Blocks ZIP path traversal (Zip Slip vulnerability).
- Ignores or rejects symlinks.
- Extracts only valid Python source files into isolated temporary sandboxes.
"""

from __future__ import annotations

import io
from pathlib import Path
import tempfile
import zipfile
from typing import Iterator

MAX_FILE_SIZE = 2 * 1024 * 1024       # 2 MB for individual Python files
MAX_ZIP_SIZE = 10 * 1024 * 1024       # 10 MB for ZIP archives
MAX_EXTRACTED_FILES = 100             # Max Python files allowed in one scan
ALLOWED_EXTENSIONS = {".py"}


class UploadSecurityError(Exception):
    """Raised when an uploaded file violates security or size constraints."""
    pass


class UploadService:
    """Safely extracts and validates uploaded Python files and archives."""

    @staticmethod
    def extract_zip(zip_bytes: bytes, destination_dir: Path) -> list[Path]:
        """Safely extract Python files from ZIP archive while preventing Zip Slip attacks."""
        if len(zip_bytes) > MAX_ZIP_SIZE:
            raise UploadSecurityError(
                f"ZIP archive size ({len(zip_bytes)} bytes) exceeds maximum limit of {MAX_ZIP_SIZE} bytes."
            )

        extracted_files: list[Path] = []
        dest_canonical = destination_dir.resolve()

        try:
            with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as zf:
                infolist = zf.infolist()
                if len(infolist) > MAX_EXTRACTED_FILES:
                    raise UploadSecurityError(
                        f"Archive contains {len(infolist)} files; maximum allowed is {MAX_EXTRACTED_FILES}."
                    )

                for member in infolist:
                    # Ignore directories
                    if member.is_dir():
                        continue

                    # Prevent symlink attacks (check Unix mode flags if present)
                    unix_mode = member.external_attr >> 16
                    if unix_mode and (unix_mode & 0o120000) == 0o120000:
                        # Symlink detected: skip or reject
                        continue

                    # Validate extension
                    target_suffix = Path(member.filename).suffix.lower()
                    if target_suffix not in ALLOWED_EXTENSIONS:
                        continue

                    # Defense against ZIP path traversal (Zip Slip):
                    # Canonical target path MUST reside strictly inside destination directory
                    target_path = (destination_dir / member.filename).resolve()
                    if not str(target_path).startswith(str(dest_canonical)):
                        raise UploadSecurityError(
                            f"Path traversal detected in archive entry: '{member.filename}'."
                        )

                    # Extract file
                    target_path.parent.mkdir(parents=True, exist_ok=True)
                    with zf.open(member) as src_file, open(target_path, "wb") as dst_file:
                        dst_file.write(src_file.read(MAX_FILE_SIZE))

                    extracted_files.append(target_path)

        except zipfile.BadZipFile as exc:
            raise UploadSecurityError(f"Invalid or corrupted ZIP archive: {exc}")

        return extracted_files

    @staticmethod
    def save_single_file(file_bytes: bytes, filename: str, destination_dir: Path) -> Path:
        """Safely save a single uploaded Python source file."""
        if len(file_bytes) > MAX_FILE_SIZE:
            raise UploadSecurityError(
                f"File size ({len(file_bytes)} bytes) exceeds maximum limit of {MAX_FILE_SIZE} bytes."
            )

        safe_name = Path(filename).name
        if not safe_name.endswith(".py"):
            safe_name += ".py"

        target_path = (destination_dir / safe_name).resolve()
        if not str(target_path).startswith(str(destination_dir.resolve())):
            raise UploadSecurityError(f"Invalid file name '{filename}'.")

        target_path.write_bytes(file_bytes)
        return target_path
