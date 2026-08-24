from __future__ import annotations

import io
from typing import Optional, Tuple

import imagehash
from PIL import Image, UnidentifiedImageError


class ImageValidationError(Exception):
    pass


def validate_and_hash(
    raw: bytes, content_type: str, max_bytes: int
) -> Tuple[str, Image.Image]:
    """Validate the uploaded image and return its 64-bit dHash (hex) + PIL image.

    Uses a difference hash (dHash) which is robust to re-encoding, resizing,
    mild JPEG recompression, and small crops — exactly the transformations a
    person would apply when re-uploading a screenshot they already submitted.
    """
    if len(raw) > max_bytes:
        raise ImageValidationError(
            f"File is too large ({len(raw) / (1024 * 1024):.1f} MB). "
            f"Maximum is {max_bytes // (1024 * 1024)} MB."
        )
    if content_type not in {"image/jpeg", "image/png", "image/webp"}:
        raise ImageValidationError("Only JPG, PNG, or WebP images are accepted.")
    try:
        img = Image.open(io.BytesIO(raw))
        img.load()
    except (UnidentifiedImageError, OSError):
        raise ImageValidationError(
            "That file doesn't look like a valid image."
        )
    if img.format not in {"JPEG", "PNG", "WEBP"}:
        raise ImageValidationError("Only JPG, PNG, or WebP images are accepted.")
    # Normalize orientation & color mode for stable hashing.
    try:
        from PIL import ImageOps

        img = ImageOps.exif_transpose(img)
    except Exception:
        pass
    if img.mode not in ("RGB", "L"):
        img = img.convert("RGB")
    dhash = imagehash.dhash(img, hash_size=8)  # 64-bit
    return str(dhash), img


def hamming_hex(a: str, b: str) -> int:
    """Hamming distance between two 64-bit hex dhash strings."""
    try:
        x = int(a, 16)
        y = int(b, 16)
    except (TypeError, ValueError):
        return 64
    return (x ^ y).bit_count()


def thumbnail_data_url(img: Image.Image, max_side: int = 320) -> str:
    """Generate a small JPEG data URL for admin previews — avoids exposing
    the raw upload URL path in the admin HTML and keeps previews snappy."""
    import base64

    thumb = img.copy()
    thumb.thumbnail((max_side, max_side))
    if thumb.mode != "RGB":
        thumb = thumb.convert("RGB")
    buf = io.BytesIO()
    thumb.save(buf, format="JPEG", quality=70)
    b64 = base64.b64encode(buf.getvalue()).decode("ascii")
    return f"data:image/jpeg;base64,{b64}"
