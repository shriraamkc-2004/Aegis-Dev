"""
Aegis Copilot — MinIO Document Storage Service
Stores PDFs, audit reports, playbooks, knowledge documents, investigation artifacts.
Persists only metadata inside PostgreSQL.
"""

from __future__ import annotations

import logging
import io
import uuid
import time
from typing import Optional, Dict, Any, List

from minio import Minio
from minio.error import S3Error

from copilot.config import (
    MINIO_ENDPOINT,
    MINIO_ACCESS_KEY,
    MINIO_SECRET_KEY,
    MINIO_USE_SSL,
    MINIO_BUCKET,
)

logger = logging.getLogger(__name__)


class StorageService:
    """
    MinIO object storage client for enterprise document management.
    """

    def __init__(
        self,
        endpoint: str = MINIO_ENDPOINT,
        access_key: str = MINIO_ACCESS_KEY,
        secret_key: str = MINIO_SECRET_KEY,
        use_ssl: bool = MINIO_USE_SSL,
        bucket: str = MINIO_BUCKET,
    ):
        self._client = Minio(
            endpoint,
            access_key=access_key,
            secret_key=secret_key,
            secure=use_ssl,
        )
        self._bucket = bucket

    # ─── Bucket Lifecycle ────────────────────────────────────────────────────────

    def ensure_bucket(self) -> None:
        """Create the document bucket if it doesn't exist."""
        try:
            if not self._client.bucket_exists(self._bucket):
                self._client.make_bucket(self._bucket)
                logger.info("Created MinIO bucket: '%s'", self._bucket)
            else:
                logger.info("MinIO bucket '%s' already exists.", self._bucket)
        except Exception as exc:
            logger.warning("MinIO bucket check failed: %s", exc)

    # ─── Upload ──────────────────────────────────────────────────────────────────

    def upload_file(
        self,
        file_data: bytes,
        filename: str,
        content_type: str = "application/octet-stream",
        metadata: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        Upload a file to MinIO.
        Returns {storage_path, object_name, size, uploaded_at}.
        """
        object_name = f"{uuid.uuid4().hex}/{filename}"
        data = io.BytesIO(file_data)
        size = len(file_data)

        try:
            self._client.put_object(
                bucket_name=self._bucket,
                object_name=object_name,
                data=data,
                length=size,
                content_type=content_type,
                metadata=metadata or {},
            )
            logger.info("Uploaded '%s' (%d bytes) → %s", filename, size, object_name)
        except S3Error as exc:
            logger.error("MinIO upload error: %s", exc)
            raise

        return {
            "storage_path": f"{self._bucket}/{object_name}",
            "object_name": object_name,
            "filename": filename,
            "size": size,
            "content_type": content_type,
            "uploaded_at": time.time(),
        }

    def upload_from_path(
        self,
        local_path: str,
        filename: Optional[str] = None,
        content_type: str = "application/octet-stream",
    ) -> Dict[str, Any]:
        """Upload a file from a local filesystem path."""
        import os
        fname = filename or os.path.basename(local_path)
        with open(local_path, "rb") as f:
            data = f.read()
        return self.upload_file(data, fname, content_type)

    # ─── Download ────────────────────────────────────────────────────────────────

    def download_file(self, object_name: str) -> bytes:
        """Download a file from MinIO by object name."""
        try:
            response = self._client.get_object(self._bucket, object_name)
            data = response.read()
            response.close()
            response.release_conn()
            return data
        except S3Error as exc:
            logger.error("MinIO download error: %s", exc)
            raise

    def get_presigned_url(self, object_name: str, expires_hours: int = 24) -> str:
        """Generate a presigned download URL."""
        from datetime import timedelta
        url = self._client.presigned_get_object(
            self._bucket, object_name, expires=timedelta(hours=expires_hours)
        )
        return url

    # ─── List / Delete ───────────────────────────────────────────────────────────

    def list_objects(self, prefix: str = "") -> List[Dict[str, Any]]:
        """List all objects in the bucket with optional prefix filter."""
        objects = []
        try:
            for obj in self._client.list_objects(self._bucket, prefix=prefix, recursive=True):
                objects.append({
                    "object_name": obj.object_name,
                    "size": obj.size,
                    "last_modified": str(obj.last_modified) if obj.last_modified else "",
                })
        except Exception as exc:
            logger.warning("MinIO list error: %s", exc)
        return objects

    def delete_object(self, object_name: str) -> None:
        """Delete a single object from MinIO."""
        try:
            self._client.remove_object(self._bucket, object_name)
            logger.info("Deleted object: %s", object_name)
        except S3Error as exc:
            logger.error("MinIO delete error: %s", exc)
            raise

    # ─── Health ──────────────────────────────────────────────────────────────────

    def is_healthy(self) -> bool:
        try:
            return self._client.bucket_exists(self._bucket)
        except Exception:
            return False
