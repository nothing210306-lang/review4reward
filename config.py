from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).parent


def _load_dotenv() -> None:
    for name in (".env", ".env.local"):
        env_path = BASE_DIR / name
        if not env_path.exists():
            continue
        for raw in env_path.read_text().splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            os.environ.setdefault(key, value)


_load_dotenv()
UPLOAD_DIR = BASE_DIR / "uploads"
# Only used for local disk-fallback storage. Serverless (Vercel) has a
# read-only filesystem, so don't try to create it there — the app uses
# Supabase Storage instead when env vars are present.
if not os.environ.get("VERCEL"):
    try:
        UPLOAD_DIR.mkdir(exist_ok=True)
    except OSError:
        pass
DB_PATH = BASE_DIR / "app.db"


def _env(key: str, default: str = "") -> str:
    return os.environ.get(key, default).strip()


SESSION_SECRET = _env("SESSION_SECRET", "dev-insecure-secret-change-me")

PUBLIC_URL = _env("PUBLIC_URL")  # may be empty; filled at runtime from request

ADMIN_EMAILS = {
    e.strip().lower()
    for e in _env("ADMIN_EMAILS", "process-optimization@envisystech.com").split(",")
    if e.strip()
}

GOOGLE_CLIENT_ID = _env("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = _env("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_PATH = "/auth/google/callback"

RESEND_API_KEY = _env("RESEND_API_KEY")
EMAIL_FROM = _env("EMAIL_FROM", "Review for Reward <onboarding@resend.dev>")

TWILIO_ACCOUNT_SID = _env("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = _env("TWILIO_AUTH_TOKEN")
TWILIO_FROM_NUMBER = _env("TWILIO_FROM_NUMBER")

BLOB_READ_WRITE_TOKEN = _env("BLOB_READ_WRITE_TOKEN")

# Supabase (Storage + Postgres). DATABASE_URL is read directly in db.py.
SUPABASE_URL = _env("SUPABASE_URL")
SUPABASE_ANON_KEY = _env("SUPABASE_ANON_KEY")
SUPABASE_SERVICE_KEY = _env("SUPABASE_SERVICE_KEY")

# Firebase (Phone auth)
FIREBASE_API_KEY = _env("FIREBASE_API_KEY")
FIREBASE_PROJECT_ID = _env("FIREBASE_PROJECT_ID")
FIREBASE_APP_ID = _env("FIREBASE_APP_ID")
FIREBASE_MESSAGING_SENDER_ID = _env("FIREBASE_MESSAGING_SENDER_ID")
FIREBASE_AUTH_DOMAIN = _env("FIREBASE_AUTH_DOMAIN") or (
    f"{FIREBASE_PROJECT_ID}.firebaseapp.com" if FIREBASE_PROJECT_ID else ""
)

FIREBASE_ENABLED = bool(FIREBASE_API_KEY and FIREBASE_PROJECT_ID and FIREBASE_APP_ID)

DUPLICATE_THRESHOLD = int(_env("DUPLICATE_THRESHOLD", "8"))
OTP_TTL_SECONDS = int(_env("OTP_TTL_SECONDS", "300"))
OTP_MAX_PER_HOUR = int(_env("OTP_MAX_PER_HOUR", "5"))

MAX_UPLOAD_MB = 12
ALLOWED_CONTENT_TYPES = {"image/jpeg", "image/png", "image/webp"}

# Derived feature flags
GOOGLE_ENABLED = bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET)
EMAIL_ENABLED = bool(RESEND_API_KEY)
SMS_ENABLED = bool(TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN and TWILIO_FROM_NUMBER)
BLOB_ENABLED = bool(BLOB_READ_WRITE_TOKEN)
