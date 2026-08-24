from __future__ import annotations

import hashlib
import hmac
import secrets
from typing import Optional

from fastapi import Request, Response
from itsdangerous import BadSignature, URLSafeTimedSerializer
from sqlalchemy.orm import Session

import config
from db import User

COOKIE_NAME = "r4r_session"
COOKIE_MAX_AGE = 60 * 60 * 24 * 30  # 30 days

_serializer = URLSafeTimedSerializer(config.SESSION_SECRET, salt="r4r-session")


def create_session_cookie(response: Response, user_id: int, secure: bool = False) -> None:
    token = _serializer.dumps({"uid": user_id})
    response.set_cookie(
        COOKIE_NAME,
        token,
        max_age=COOKIE_MAX_AGE,
        httponly=True,
        samesite="lax",
        secure=secure or (config.PUBLIC_URL.startswith("https://") if config.PUBLIC_URL else False),
        path="/",
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(COOKIE_NAME, path="/")


def read_session_user_id(request: Request) -> Optional[int]:
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return None
    try:
        data = _serializer.loads(token, max_age=COOKIE_MAX_AGE)
        return int(data.get("uid"))
    except (BadSignature, ValueError, TypeError):
        return None


def load_user(db: Session, request: Request) -> Optional[User]:
    uid = read_session_user_id(request)
    if uid is None:
        return None
    return db.get(User, uid)


def hash_otp(code: str) -> str:
    return hashlib.sha256(("r4r-otp:" + code).encode()).hexdigest()


def verify_otp_hash(code: str, expected_hash: str) -> bool:
    return hmac.compare_digest(hash_otp(code), expected_hash)


def generate_otp() -> str:
    # 6-digit numeric code, zero-padded
    return f"{secrets.randbelow(1_000_000):06d}"


def is_admin_user(user: User) -> bool:
    """The ONLY trusted admin check: is the user's verified Google email
    present in the server-side allowlist? Client flags are never consulted."""
    if user is None:
        return False
    provider = getattr(user, "provider", None)
    if provider != "google":
        return False
    email = getattr(user, "email", None)
    if not email:
        return False
    return email.strip().lower() in config.ADMIN_EMAILS
