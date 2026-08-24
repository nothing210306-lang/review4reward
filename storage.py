"""Image storage abstraction.

Production (Vercel + Supabase): uploads go direct from the browser to a
private Supabase Storage bucket using a short-lived signed URL. The API then
streams the object back once to compute the dHash and run the duplicate check,
and stores the object's path in the database. We never route the 12 MB file
through a Vercel function, bypassing the 4.5 MB function body limit.

Local/dev: files are written to disk under `uploads/` and served by the app.
"""
from __future__ import annotations

import logging
import secrets
from pathlib import Path
from typing import Tuple

import httpx

import config

log = logging.getLogger("storage")

BUCKET = "review-screenshots"


# --------------------------- feature detection ----------------------------

def supabase_enabled() -> bool:
    return bool(config.SUPABASE_URL and config.SUPABASE_SERVICE_KEY)


# --------------------------- local disk fallback --------------------------

async def save_upload_disk(raw: bytes, content_type: str, filename: str) -> Tuple[str, str]:
    """Local-dev disk storage. Never called on Vercel (filesystem is read-only);
    the Supabase path is used when SUPABASE_SERVICE_KEY is set."""
    config.UPLOAD_DIR.mkdir(exist_ok=True)
    ext = _ext_for(content_type, filename)
    oid = secrets.token_hex(12)
    object_name = f"{oid}{ext}"
    dest = config.UPLOAD_DIR / object_name
    dest.write_bytes(raw)
    return f"/uploads/{object_name}", "disk"


def _ext_for(content_type: str, filename: str) -> str:
    if content_type == "image/png":
        return ".png"
    if content_type == "image/webp":
        return ".webp"
    if "." in filename:
        suffix = Path(filename).suffix.lower()
        if suffix in {".jpg", ".jpeg", ".png", ".webp"}:
            return suffix
    return ".jpg"


# --------------------------- Supabase Storage -----------------------------

def _supabase_headers() -> dict:
    return {
        "Authorization": f"Bearer {config.SUPABASE_SERVICE_KEY}",
        "apikey": config.SUPABASE_SERVICE_KEY,
        "Content-Type": "application/json",
    }


def ensure_bucket() -> None:
    """Create a private storage bucket and a permissive RLS policy if needed.
    Safe to call on startup; uses upsert semantics."""
    if not supabase_enabled():
        return
    base = config.SUPABASE_URL.rstrip("/")
    try:
        with httpx.Client(timeout=20) as client:
            # Check existence first.
            r = client.get(f"{base}/storage/v1/bucket/{BUCKET}", headers=_supabase_headers())
            if r.status_code == 404:
                client.post(
                    f"{base}/storage/v1/bucket",
                    headers=_supabase_headers(),
                    json={
                        "id": BUCKET,
                        "name": BUCKET,
                        "public": False,
                        "file_size_limit": 15 * 1024 * 1024,
                        "allowed_mime_types": ["image/jpeg", "image/png", "image/webp"],
                    },
                )
                log.info("Created Supabase storage bucket %s", BUCKET)
            # Make bucket public=false is enough because service-role key bypasses RLS.
    except Exception as exc:  # noqa: BLE001
        log.warning("Could not ensure Supabase bucket: %s", exc)


def create_signed_upload_url(object_path: str, content_type: str) -> str:
    """Ask Supabase Storage for a short-lived signed URL the browser can
    PUT the file to directly. Returns the URL the browser should PUT to."""
    base = config.SUPABASE_URL.rstrip("/")
    with httpx.Client(timeout=20) as client:
        r = client.post(
            f"{base}/storage/v1/object/upload/sign/{BUCKET}/{object_path}",
            headers=_supabase_headers(),
            json={},
        )
        r.raise_for_status()
        token = r.json()["token"]
    # The browser PUTs to /storage/v1/object/upload/sign/{bucket}/{path}?token=...
    return f"{base}/storage/v1/object/upload/sign/{BUCKET}/{object_path}?token={token}"


def create_signed_download_url(object_path: str, expires_in: int = 60 * 60 * 24 * 7) -> str:
    """Return a time-limited public URL for viewing the image."""
    base = config.SUPABASE_URL.rstrip("/")
    with httpx.Client(timeout=20) as client:
        r = client.post(
            f"{base}/storage/v1/object/sign/{BUCKET}/{object_path}",
            headers=_supabase_headers(),
            json={"expiresIn": expires_in},
        )
        r.raise_for_status()
        signed = r.json()["signedURL"]
    # Supabase returns `/object/sign/...` (without the `/storage/v1` prefix)
    # in some API versions; normalize to the full public path.
    if signed.startswith("/object/sign/"):
        signed = "/storage/v1" + signed
    return f"{base}{signed}"


def download_object(object_path: str) -> bytes:
    """Server-side fetch of a stored object (for hashing / duplicate checks)."""
    base = config.SUPABASE_URL.rstrip("/")
    with httpx.Client(timeout=30) as client:
        r = client.get(
            f"{base}/storage/v1/object/{BUCKET}/{object_path}",
            headers=_supabase_headers(),
        )
        r.raise_for_status()
        return r.content


def commit_signed_upload(object_path: str) -> None:
    """Confirm the browser's signed upload completed successfully so it's
    visible to subsequent downloads. Called by the API after the PUT returns."""
    base = config.SUPABASE_URL.rstrip("/")
    with httpx.Client(timeout=20) as client:
        r = client.get(
            f"{base}/storage/v1/object/{BUCKET}/{object_path}",
            headers=_supabase_headers(),
        )
        r.raise_for_status()
