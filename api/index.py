"""Vercel serverless entrypoint.

The @vercel/python builder wraps this module as a WSGI/ASGI handler. We expose
the FastAPI `app` object so `vc_init` / Mangum-style adapters can serve it.
Vercel's Python runtime imports `api/index.app`.
"""
import sys
from pathlib import Path

# Make the project root importable so `import app` works.
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import app  # noqa: E402,F401

# Vercel's Python runtime expects either an `app` (ASGI) or `handler`.
__all__ = ["app"]
