from __future__ import annotations

import csv
import io
import logging
import os
import secrets
from collections import Counter
from datetime import timedelta
from pathlib import Path
from typing import List, Optional, Tuple

import httpx
from fastapi import (
    Depends,
    FastAPI,
    File,
    Form,
    HTTPException,
    Request,
    Response,
    UploadFile,
    status,
)
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
    StreamingResponse,
)
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi.templating import Jinja2Templates
from itsdangerous import BadSignature, URLSafeTimedSerializer
from sqlalchemy import func, select
from sqlalchemy.orm import Session

import auth
import config
import firebase_auth
import google_auth
import notifications
import storage
from db import AuditLog, Notification, OtpChallenge, Submission, User, get_db, init_db, utcnow
from image_utils import ImageValidationError, hamming_hex, validate_and_hash

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("app")

app = FastAPI(title="Review for Reward", docs_url=None, redoc_url=None)
_static_dir = config.BASE_DIR / "static"
if _static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(_static_dir)), name="static")
if config.UPLOAD_DIR.exists():
    app.mount("/uploads", StaticFiles(directory=str(config.UPLOAD_DIR)), name="uploads")
templates = Jinja2Templates(directory=str(config.BASE_DIR / "templates"))
_orig_template_response = templates.TemplateResponse


def _template_response(name: str, ctx: dict, **kw):
    # Starlette 1.x wants (request, name, context). Our call sites pass
    # (name, context) — pull request out and forward it.
    request = ctx.get("request")
    return _orig_template_response(request, name, ctx, **kw)


templates.TemplateResponse = _template_response  # type: ignore[assignment]

_flash_serializer = URLSafeTimedSerializer(config.SESSION_SECRET, salt="r4r-flash")


class FlashMiddleware(BaseHTTPMiddleware):
    """Reads the signed one-time `flash` cookie, attaches its message to the
    request state for templates, and clears the cookie so it only shows once."""

    async def dispatch(self, request: Request, call_next):
        flash = None
        raw = request.cookies.get("flash")
        if raw:
            try:
                data = _flash_serializer.loads(raw, max_age=30)
                flash = {"message": data.get("m", ""), "kind": data.get("k", "info")}
            except (BadSignature, ValueError, TypeError):
                flash = None
        request.state.flash = flash
        response = await call_next(request)
        if flash is not None:
            response.delete_cookie("flash", path="/")
        return response


app.add_middleware(FlashMiddleware)


@app.middleware("http")
async def _add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    return response


@app.on_event("startup")
def _startup() -> None:
    init_db()
    if storage.supabase_enabled():
        storage.ensure_bucket()
    log.info("Admins allowlist: %s", config.ADMIN_EMAILS)
    log.info(
        "Providers — google=%s email=%s sms=%s storage=%s db=%s",
        config.GOOGLE_ENABLED,
        config.EMAIL_ENABLED,
        config.SMS_ENABLED,
        "supabase" if storage.supabase_enabled() else "disk",
        "postgres" if os.environ.get("DATABASE_URL") else "sqlite",
    )


# ----------------------------- helpers ----------------------------------

def base_url(request: Request) -> str:
    if config.PUBLIC_URL:
        return config.PUBLIC_URL.rstrip("/")
    # Behind a TLS-terminating proxy, prefer X-Forwarded-* so OAuth redirect
    # URIs and secure-cookie flags use the public https origin.
    proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    host = request.headers.get("x-forwarded-host", request.headers.get("host", ""))
    if host:
        return f"{proto}://{host}".rstrip("/")
    return str(request.base_url).rstrip("/")


def client_ip(request: Request) -> str:
    fw = request.headers.get("x-forwarded-for", "")
    if fw:
        return fw.split(",")[0].strip()
    return request.client.host if request.client else "?"


def audit(
    db: Session,
    request: Request,
    action: str,
    detail: Optional[str] = None,
    user: Optional[User] = None,
) -> None:
    db.add(
        AuditLog(
            actor_user_id=user.id if user else None,
            actor_label=(user.email or user.phone) if user else None,
            action=action,
            detail=detail,
            ip=client_ip(request),
        )
    )


def _public_image_url(stored_url: str) -> str:
    """Convert a stored `image_url` (disk path or supabase:// path) into a URL
    the browser can load. Supabase objects are returned as short-lived signed
    URLs so the bucket can remain private."""
    if not stored_url:
        return ""
    if stored_url.startswith("supabase://"):
        path = stored_url[len("supabase://"):]
        try:
            return storage.create_signed_download_url(path, expires_in=60 * 60 * 12)
        except Exception:  # noqa: BLE001
            log.exception("signed url failed for %s", path)
            return ""
    return stored_url


def _decorate(sub):
    """Attach a browser-loadable `image_public_url` to a submission object."""
    try:
        sub.image_public_url = _public_image_url(sub.image_url)
    except Exception:  # noqa: BLE001
        sub.image_public_url = ""
    return sub


def context(request: Request, user: Optional[User], **extra) -> dict:
    ctx = {
        "request": request,
        "user": user,
        "is_admin": auth.is_admin_user(user),
        "flash": getattr(request.state, "flash", None),
        "active": extra.pop("active", ""),
    }
    ctx.update(extra)
    return ctx


def require_user(request: Request, db: Session) -> User:
    user = auth.load_user(db, request)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not signed in")
    user.last_login_at = utcnow()
    return user


def require_admin(request: Request, db: Session) -> User:
    """Server-side admin gate. Returns the user ONLY if their verified Google
    email is on the allowlist. Everyone else gets a generic 404 so admin
    resources can't be discovered."""
    user = auth.load_user(db, request)
    if not auth.is_admin_user(user):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    return user  # type: ignore[return-value]


# ------------------------------- pages ----------------------------------

@app.get("/", response_class=HTMLResponse)
def landing(request: Request, db: Session = Depends(get_db)):
    """Public animated splash/landing page for logged-out visitors."""
    user = auth.load_user(db, request)
    if user:
        if not user.profile_complete:
            return RedirectResponse("/profile", status_code=303)
        return RedirectResponse("/dashboard", status_code=303)
    return templates.TemplateResponse("splash.html", {"request": request})


@app.get("/dashboard", response_class=HTMLResponse)
def home(request: Request, db: Session = Depends(get_db)):
    user = auth.load_user(db, request)
    if not user:
        return RedirectResponse("/dashboard", status_code=303)
    if not user.profile_complete:
        return RedirectResponse("/profile", status_code=303)

    submissions = (
        db.query(Submission)
        .filter(Submission.user_id == user.id)
        .order_by(Submission.created_at.desc())
        .limit(50)
        .all()
    )
    for s in submissions:
        _decorate(s)
    approved_count = sum(1 for s in submissions if s.status == "approved")
    return templates.TemplateResponse(
        "submit.html",
        context(
            request, user,
            submissions=submissions,
            approved_count=approved_count,
            max_mb=config.MAX_UPLOAD_MB,
            direct_upload=storage.supabase_enabled(),
            active="submit",
        ),
    )


@app.get("/signin", response_class=HTMLResponse)
def signin_page(request: Request, db: Session = Depends(get_db)):
    user = auth.load_user(db, request)
    if user:
        return RedirectResponse("/dashboard", status_code=303)
    is_prod = bool(os.environ.get("SERVERLESS") or os.environ.get("VERCEL"))
    return templates.TemplateResponse(
        "signin.html",
        {
            "request": request,
            "user": None,
            "dev_google": not config.GOOGLE_ENABLED and not is_prod,
            "prod_no_auth": is_prod and not config.GOOGLE_ENABLED,
            # Phone auth via Firebase is the production path; the old
            # Twilio/OTP form remains available for local dev.
            "firebase_enabled": config.FIREBASE_ENABLED,
            "firebase_config": {
                "apiKey": config.FIREBASE_API_KEY,
                "authDomain": config.FIREBASE_AUTH_DOMAIN,
                "projectId": config.FIREBASE_PROJECT_ID,
                "appId": config.FIREBASE_APP_ID,
                "messagingSenderId": config.FIREBASE_MESSAGING_SENDER_ID,
            } if config.FIREBASE_ENABLED else None,
            "phone_enabled": config.SMS_ENABLED or (not is_prod and not config.FIREBASE_ENABLED),
            "error": request.query_params.get("error"),
            "otp_sent": None,
        },
    )


@app.get("/profile", response_class=HTMLResponse)
def profile_page(request: Request, db: Session = Depends(get_db)):
    user = auth.load_user(db, request)
    if not user:
        return RedirectResponse("/signin", status_code=303)

    prefill = user.full_name or (user.email.split("@")[0] if user.email else "")
    return templates.TemplateResponse(
        "profile.html",
        context(request, user, prefill_name=prefill, error=request.query_params.get("error")),
    )


@app.post("/profile")
def profile_submit(
    request: Request,
    full_name: str = Form(...),
    department: str = Form(""),
    role: str = Form(""),
    email: str = Form(""),
    phone: str = Form(""),
    db: Session = Depends(get_db),
):
    user = auth.load_user(db, request)
    if not user:
        return RedirectResponse("/signin", status_code=303)
    name = (full_name or "").strip()
    if len(name) < 2:
        return RedirectResponse("/profile?error=Please+enter+your+full+name.", status_code=303)

    # Email: only set if the user signed in via phone (Google users keep their verified email).
    email_val = (email or "").strip().lower()
    if email_val and user.provider != "google":
        # basic format check
        import re as _re
        if not _re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", email_val):
            return RedirectResponse("/profile?error=Please+enter+a+valid+email+address.", status_code=303)
        # uniqueness
        existing = db.query(User).filter(User.email == email_val, User.id != user.id).first()
        if existing:
            return RedirectResponse("/profile?error=That+email+is+already+in+use.", status_code=303)
        user.email = email_val
    elif not email_val and user.provider != "google":
        user.email = None

    # Phone: only set if the user signed in via Google (phone users keep their verified number).
    phone_val = _normalize_phone((phone or "").strip())
    if phone_val and user.provider != "phone":
        existing = db.query(User).filter(User.phone == phone_val, User.id != user.id).first()
        if existing:
            return RedirectResponse("/profile?error=That+phone+number+is+already+in+use.", status_code=303)
        user.phone = phone_val
    elif not phone_val and user.provider != "phone":
        user.phone = None

    user.full_name = name[:200]
    user.department = (department or "").strip()[:200] or None
    user.role = (role or "").strip()[:200] or None
    user.profile_complete = 1
    audit(db, request, "profile_completed", f"name={name}", user=user)
    db.commit()
    response = RedirectResponse("/dashboard", status_code=303)
    return response


@app.get("/leaderboard", response_class=HTMLResponse)
def leaderboard_page(request: Request, db: Session = Depends(get_db)):
    user = auth.load_user(db, request)
    rows = leaderboard_rows(db)
    return templates.TemplateResponse(
        "leaderboard.html",
        context(request, user, rows=rows, active="leaderboard"),
    )


def leaderboard_rows(db: Session) -> List[dict]:
    results = (
        db.query(
            Submission.user_id,
            User.full_name,
            User.email,
            User.phone,
            User.department,
            User.role,
            func.count(Submission.id).label("approved"),
        )
        .join(User, User.id == Submission.user_id)
        .filter(Submission.status == "approved")
        .group_by(
            Submission.user_id,
            User.full_name, User.email, User.phone, User.department, User.role,
        )
        .order_by(func.count(Submission.id).desc(), User.full_name.asc())
        .all()
    )
    return [
        {
            "user_id": r.user_id,
            "name": r.full_name,
            "email": r.email,
            "phone": r.phone,
            "department": r.department,
            "role": r.role,
            "approved": r.approved,
        }
        for r in results
    ]


# ----------------------------- Google OAuth ------------------------------

@app.get("/auth/google/login")
def google_login(request: Request):
    if not config.GOOGLE_ENABLED:
        return RedirectResponse("/signin?error=Google+sign-in+is+not+configured.", status_code=303)
    state = secrets.token_urlsafe(24)
    request.session_state = state  # not stored; use signed cookie instead
    response = RedirectResponse(
        google_auth.build_authorization_url(state, base_url(request)), status_code=303
    )
    response.set_cookie(
        "g_oauth_state", state, httponly=True, samesite="lax", max_age=600,
        secure=base_url(request).startswith("https"),
    )
    return response


@app.get("/auth/google/callback")
async def google_callback(
    request: Request,
    code: Optional[str] = None,
    state: Optional[str] = None,
    error: Optional[str] = None,
    db: Session = Depends(get_db),
):
    if error:
        return RedirectResponse(f"/signin?error={error}", status_code=303)
    cookie_state = request.cookies.get("g_oauth_state")
    if not state or not cookie_state or not secrets.compare_digest(state, cookie_state):
        return RedirectResponse("/signin?error=Sign-in+state+mismatch.+Try+again.", status_code=303)
    if not code or not config.GOOGLE_ENABLED:
        return RedirectResponse("/signin?error=Sign-in+failed.", status_code=303)
    try:
        email, name, _picture = await google_auth.exchange_code_for_user(code, base_url(request))
    except Exception as exc:  # noqa: BLE001
        log.exception("Google auth failed: %s", exc)
        return RedirectResponse("/signin?error=Google+verification+failed.", status_code=303)

    user = db.query(User).filter(User.provider == "google", User.email == email).first()
    is_new = user is None
    if is_new:
        user = User(
            provider="google", email=email, full_name=name,
            is_admin=1 if email.lower() in config.ADMIN_EMAILS else 0,
        )
        db.add(user)
        db.flush()
        audit(db, request, "signup", f"google {email}", user=user)
    else:
        # Re-evaluate admin from allowlist on every login (never trust stored flag).
        user.is_admin = 1 if email.lower() in config.ADMIN_EMAILS else 0
    user.last_login_at = utcnow()
    audit(db, request, "signin", f"google {email}", user=user)
    db.commit()

    target = "/admin" if user.is_admin else ("/profile" if is_new or not user.profile_complete else "/")
    response = RedirectResponse(target, status_code=303)
    response.delete_cookie("g_oauth_state")
    auth.create_session_cookie(response, user.id, secure=base_url(request).startswith("https"))
    return response


@app.post("/auth/google/dev")
def google_dev(
    request: Request,
    email: str = Form(...),
    db: Session = Depends(get_db),
):
    """Dev-only simulated Google sign-in. Only reachable when (a) GOOGLE
    credentials are absent AND (b) we're not running on a serverless/production
    host — so the deployed site can never be exploited to impersonate an
    allowed admin by typing their email."""
    if config.GOOGLE_ENABLED or os.environ.get("SERVERLESS") or os.environ.get("VERCEL"):
        raise HTTPException(status_code=404)
    clean = (email or "").strip().lower()
    if not clean or "@" not in clean:
        return RedirectResponse("/signin?error=Enter+a+valid+email.", status_code=303)
    user = db.query(User).filter(User.provider == "google", User.email == clean).first()
    is_new = user is None
    if is_new:
        user = User(
            provider="google", email=clean, full_name=clean.split("@")[0],
            is_admin=1 if clean in config.ADMIN_EMAILS else 0,
        )
        db.add(user)
        db.flush()
        audit(db, request, "signup_dev", f"google {clean}", user=user)
    else:
        user.is_admin = 1 if clean in config.ADMIN_EMAILS else 0
    user.last_login_at = utcnow()
    audit(db, request, "signin_dev", f"google {clean}", user=user)
    db.commit()
    target = "/admin" if user.is_admin else ("/profile" if is_new or not user.profile_complete else "/")
    response = RedirectResponse(target, status_code=303)
    auth.create_session_cookie(response, user.id, secure=base_url(request).startswith("https"))
    return response


# ---------------------------- Phone + OTP --------------------------------

def _normalize_phone(raw: str) -> str:
    digits = "".join(ch for ch in (raw or "") if ch.isdigit())
    if not digits:
        return ""
    if len(digits) == 10:
        digits = "91" + digits  # default to India when country code omitted
    return "+" + digits


@app.post("/auth/phone/request")
async def phone_request(
    request: Request,
    phone: str = Form(...),
    db: Session = Depends(get_db),
):
    normalized = _normalize_phone(phone)
    if not normalized or len(normalized) < 8:
        return RedirectResponse(
            "/signin?error=Enter+a+valid+phone+with+country+code.", status_code=303
        )
    # On production, never surface OTPs in the UI. If Twilio isn't configured,
    # phone sign-in is unavailable rather than trivially bypassable.
    is_prod = bool(os.environ.get("SERVERLESS") or os.environ.get("VERCEL"))
    if is_prod and not config.SMS_ENABLED:
        return RedirectResponse(
            "/signin?error=Phone+sign-in+is+temporarily+unavailable.+Use+Google.",
            status_code=303,
        )
    one_hour_ago = utcnow() - timedelta(hours=1)
    recent = (
        db.query(func.count(OtpChallenge.id))
        .filter(OtpChallenge.phone == normalized, OtpChallenge.created_at >= one_hour_ago)
        .scalar()
    )
    if recent >= config.OTP_MAX_PER_HOUR:
        audit(db, request, "otp_rate_limited", normalized)
        db.commit()
        return RedirectResponse(
            f"/signin?error=Too+many+codes+requested.+Try+again+in+an+hour.", status_code=303
        )

    code = auth.generate_otp()
    challenge = OtpChallenge(
        phone=normalized,
        code_hash=auth.hash_otp(code),
        expires_at=utcnow() + timedelta(seconds=config.OTP_TTL_SECONDS),
        ip=client_ip(request),
    )
    db.add(challenge)
    audit(db, request, "otp_requested", normalized)
    db.commit()

    delivered = await notifications.send_sms(
        normalized,
        f"Your Review for Reward sign-in code is {code}. It expires in 5 minutes.",
    )

    # In dev mode (no real SMS), surface the code on the sign-in page so it's testable.
    dev_otp = None if delivered or config.SMS_ENABLED else code
    return _render_signin_with_otp(request, normalized, dev_otp)


def _render_signin_with_otp(request: Request, phone: str, dev_otp: Optional[str]):
    return templates.TemplateResponse(
        "signin.html",
        {
            "request": request,
            "user": None,
            "dev_google": not config.GOOGLE_ENABLED,
            "otp_sent": phone,
            "dev_otp": dev_otp,
            "error": None,
        },
    )


@app.post("/auth/phone/verify")
def phone_verify(
    request: Request,
    phone: str = Form(...),
    code: str = Form(...),
    db: Session = Depends(get_db),
):
    normalized = _normalize_phone(phone)
    clean_code = (code or "").strip()
    if not normalized or not clean_code:
        return RedirectResponse("/signin?error=Enter+the+code+we+sent+you.", status_code=303)

    challenge = (
        db.query(OtpChallenge)
        .filter(OtpChallenge.phone == normalized, OtpChallenge.consumed == 0)
        .order_by(OtpChallenge.created_at.desc())
        .first()
    )
    now = utcnow()
    expires = challenge.expires_at if challenge is not None else None
    if not challenge or (expires is not None and expires < now) or not auth.verify_otp_hash(clean_code, challenge.code_hash):
        audit(db, request, "otp_failed", normalized)
        db.commit()
        return RedirectResponse(
            "/signin?error=That+code+is+invalid+or+expired.", status_code=303
        )
    challenge.consumed = 1

    user = db.query(User).filter(User.provider == "phone", User.phone == normalized).first()
    is_new = user is None
    if is_new:
        user = User(provider="phone", phone=normalized)
        db.add(user)
        db.flush()
        audit(db, request, "signup", f"phone {normalized}", user=user)
    user.last_login_at = now
    audit(db, request, "signin", f"phone {normalized}", user=user)
    db.commit()

    target = "/admin" if user.is_admin else ("/profile" if is_new or not user.profile_complete else "/")
    response = RedirectResponse(target, status_code=303)
    auth.create_session_cookie(response, user.id, secure=base_url(request).startswith("https"))
    return response


@app.post("/auth/logout")
def logout(request: Request):
    response = RedirectResponse("/signin", status_code=303)
    auth.clear_session_cookie(response)
    return response


# ------------------------- Firebase phone auth ----------------------------

@app.post("/auth/firebase")
async def firebase_signin(
    request: Request,
    idToken: str = Form(...),
    db: Session = Depends(get_db),
):
    """Receive a Firebase ID token after the browser completes phone OTP,
    verify it server-side against Google's public keys, and create a session
    keyed by the verified E.164 phone number."""
    if not config.FIREBASE_ENABLED:
        raise HTTPException(status_code=404)
    try:
        claims = await firebase_auth.verify_id_token(idToken, config.FIREBASE_PROJECT_ID)
    except firebase_auth.FirebaseTokenError as exc:
        log.warning("Firebase token rejected: %s", exc)
        audit(db, request, "firebase_token_rejected", str(exc)[:300])
        db.commit()
        # Always include the reason — it's a debugging detail, not a secret.
        return JSONResponse(
            {"ok": False, "error": f"Phone verification failed: {exc}"},
            status_code=401,
        )

    phone = (
        claims.get("phone_number")
        or claims.get("firebase", {}).get("identities", {}).get("phone", [None])[0]
    )
    if not phone or not str(phone).startswith("+"):
        log.warning("Firebase token missing phone_number: %s", claims)
        return JSONResponse(
            {"ok": False, "error": "No verified phone number on this credential."},
            status_code=400,
        )

    user = db.query(User).filter(User.provider == "phone", User.phone == phone).first()
    is_new = user is None
    if is_new:
        user = User(provider="phone", phone=phone)
        db.add(user)
        db.flush()
        audit(db, request, "signup", f"phone {phone}", user=user)
    user.last_login_at = utcnow()
    audit(db, request, "signin", f"phone {phone} via Firebase", user=user)
    db.commit()

    target = "/admin" if user.is_admin else ("/profile" if is_new or not user.profile_complete else "/")
    response = JSONResponse({"ok": True, "redirect": target})
    auth.create_session_cookie(response, user.id, secure=base_url(request).startswith("https"))
    return response


# ---------------------------- Upload flow --------------------------------

def _object_path_for(content_type: str, filename: str) -> Tuple[str, str]:
    ext = ".jpg"
    if content_type == "image/png":
        ext = ".png"
    elif content_type == "image/webp":
        ext = ".webp"
    elif "." in filename:
        suffix = Path(filename).suffix.lower()
        if suffix in {".jpg", ".jpeg", ".png", ".webp"}:
            ext = suffix
    return f"submissions/{secrets.token_hex(16)}{ext}", ext


@app.get("/api/upload/url")
def api_upload_url(
    request: Request,
    filename: str,
    content_type: str,
    db: Session = Depends(get_db),
):
    """Returns a short-lived signed URL the browser PUTs the screenshot to
    directly (so the 12 MB file never transits a Vercel function)."""
    user = require_user(request, db)
    if content_type not in config.ALLOWED_CONTENT_TYPES:
        raise HTTPException(status_code=400, detail="Unsupported file type.")
    if not storage.supabase_enabled():
        raise HTTPException(status_code=400, detail="Direct upload unavailable.")
    object_path, _ext = _object_path_for(content_type, filename)
    signed_url = storage.create_signed_upload_url(object_path, content_type)
    return JSONResponse(
        {
            "uploadUrl": signed_url,
            "objectPath": object_path,
            "contentType": content_type,
            "maxBytes": config.MAX_UPLOAD_MB * 1024 * 1024,
        }
    )


@app.post("/submit")
async def submit_review(
    request: Request,
    object_path: str = Form(""),
    customer_name: str = Form(""),
    notes: str = Form(""),
    # Legacy disk-mode multipart upload (only used when Supabase is absent):
    file: Optional[UploadFile] = File(None),
    db: Session = Depends(get_db),
):
    user = require_user(request, db)
    if not user.profile_complete:
        return RedirectResponse("/profile", status_code=303)

    secure = base_url(request).startswith("https")

    # ----- Fetch the raw bytes from either Supabase or multipart fallback -----
    storage_kind = "disk"
    image_url = ""
    if object_path and storage.supabase_enabled():
        # The browser PUT directly to Supabase; pull it back to hash & dedupe.
        if not object_path.startswith("submissions/") or ".." in object_path:
            return _redirect_with_flash("/", "Invalid upload reference.", "error", secure=secure)
        try:
            raw = storage.download_object(object_path)
        except Exception as exc:  # noqa: BLE001
            log.exception("download_object failed: %s", exc)
            return _redirect_with_flash(
                "/", "We couldn't retrieve the uploaded image. Please try again.",
                "error", secure=secure,
            )
        # Infer content type from object path extension.
        content_type = "image/jpeg"
        if object_path.lower().endswith(".png"):
            content_type = "image/png"
        elif object_path.lower().endswith(".webp"):
            content_type = "image/webp"
        storage_kind = "supabase"
    elif file is not None:
        raw = await file.read()
        content_type = file.content_type or ""
    else:
        return _redirect_with_flash(
            "/", "No image was uploaded. Please attach a screenshot.", "error", secure=secure,
        )

    try:
        dhash, _img = validate_and_hash(
            raw, content_type, config.MAX_UPLOAD_MB * 1024 * 1024
        )
    except ImageValidationError as exc:
        audit(db, request, "upload_rejected_validation", str(exc), user=user)
        db.commit()
        return _redirect_with_flash("/", str(exc), "error", secure=secure)

    # Anti-fraud: compare dHash against ALL prior submissions.
    prior = db.query(Submission.id, Submission.user_id, Submission.dhash).all()
    nearest = None
    nearest_dist = 999
    for sid, suser, shash in prior:
        d = hamming_hex(dhash, shash)
        if d < nearest_dist:
            nearest_dist = d
            nearest = (sid, suser)
        if d <= config.DUPLICATE_THRESHOLD:
            audit(
                db, request, "upload_duplicate_blocked",
                f"matches sub #{sid} (distance {d}) by user {suser}", user=user,
            )
            db.commit()
            return _redirect_with_flash(
                "/",
                "This screenshot looks like a re-upload of an existing review (anti-fraud check). "
                "Please submit a distinct, newly captured review.",
                "error", secure=secure,
            )

    # ----- Persist image reference -----
    if storage_kind == "supabase":
        # Store the object path; signed viewing URLs are generated at read time.
        image_url = f"supabase://{object_path}"
    else:
        disk_url, _ = await storage.save_upload_disk(raw, content_type, file.filename or "review.jpg")
        image_url = disk_url

    sub = Submission(
        user_id=user.id,
        status="under_verification",
        customer_name=(customer_name or "").strip()[:200] or None,
        notes=(notes or "").strip()[:2000] or None,
        image_url=image_url,
        image_storage=storage_kind,
        dhash=dhash,
    )
    db.add(sub)
    audit(
        db, request, "submission_created",
        f"sub #? dhash={dhash} nearest_dist={nearest_dist} storage={storage_kind}",
        user=user,
    )
    db.commit()
    db.refresh(sub)

    await notifications.notify_submission_status(db, user, "under_verification")
    db.commit()

    return _redirect_with_flash(
        "/",
        "Submitted! We're verifying your review and will notify you of the result.",
        "success", secure=secure,
    )


def _redirect_with_flash(path: str, message: str, kind: str, secure: bool = False) -> Response:
    """Simple flash via signed one-time cookie (consumed by the inline script in base.html)."""
    resp = RedirectResponse(path, status_code=303)
    s = URLSafeTimedSerializer(config.SESSION_SECRET, salt="r4r-flash")
    resp.set_cookie(
        "flash", s.dumps({"m": message, "k": kind}),
        httponly=True, samesite="lax", max_age=30,
        secure=secure or (config.PUBLIC_URL.startswith("https") if config.PUBLIC_URL else False),
        path="/",
    )
    return resp


# ------------------------------ Notifications ---------------------------

@app.get("/api/notifications")
def api_notifications(request: Request, db: Session = Depends(get_db)):
    user = auth.load_user(db, request)
    if not user:
        return JSONResponse({"items": [], "unread": 0}, status_code=401)
    items = (
        db.query(Notification)
        .filter(Notification.user_id == user.id)
        .order_by(Notification.created_at.desc())
        .limit(20)
        .all()
    )
    unread = sum(1 for n in items if not n.read)
    return JSONResponse(
        {
            "unread": unread,
            "items": [
                {
                    "kind": n.kind,
                    "body": n.body,
                    "read": bool(n.read),
                    "time": n.created_at.strftime("%d %b, %H:%M"),
                }
                for n in items
            ],
        }
    )


@app.post("/api/notifications/read")
def api_notifications_read(request: Request, db: Session = Depends(get_db)):
    user = auth.load_user(db, request)
    if not user:
        return JSONResponse({"ok": False}, status_code=401)
    db.query(Notification).filter(Notification.user_id == user.id, Notification.read == 0).update(
        {Notification.read: 1}
    )
    db.commit()
    return JSONResponse({"ok": True})


# --------------------------- Hidden admin area ---------------------------
# Every admin route re-checks the allowlist via require_admin. There is no
# link to /admin anywhere in the UI for non-admins, and unauthenticated or
# non-allowlisted callers receive a generic 404 (so the area's existence is
# not disclosed).

@app.get("/admin", response_class=HTMLResponse)
def admin_home(request: Request, db: Session = Depends(get_db)):
    user = require_admin(request, db)
    pending = (
        db.query(Submission)
        .filter(Submission.status.in_(["pending", "under_verification"]))
        .order_by(Submission.created_at.asc())
        .all()
    )
    approved = (
        db.query(Submission).filter(Submission.status == "approved")
        .order_by(Submission.decided_at.desc()).limit(100).all()
    )
    rejected = (
        db.query(Submission).filter(Submission.status == "rejected")
        .order_by(Submission.decided_at.desc()).limit(100).all()
    )
    for s in pending + approved + rejected:
        _decorate(s)
    audit_events = db.query(AuditLog).order_by(AuditLog.ts.desc()).limit(300).all()
    counts = {
        "pending": len(pending),
        "approved": db.query(func.count(Submission.id)).filter(Submission.status == "approved").scalar() or 0,
        "rejected": db.query(func.count(Submission.id)).filter(Submission.status == "rejected").scalar() or 0,
    }
    return templates.TemplateResponse(
        "admin.html",
        context(
            request, user,
            pending=pending, approved=approved, rejected=rejected,
            counts=counts, audit=audit_events, active="admin",
        ),
    )


@app.post("/admin/submissions/approve-all")
async def admin_approve_all(request: Request, db: Session = Depends(get_db)):
    admin = require_admin(request, db)
    pending = db.query(Submission).filter(Submission.status.in_(["pending", "under_verification"])).all()
    count = 0
    now = utcnow()
    for sub in pending:
        sub.status = "approved"
        sub.decided_at = now
        sub.rejection_reason = None
        submitter = db.get(User, sub.user_id)
        if submitter:
            await notifications.notify_submission_status(db, submitter, "approved")
        count += 1
    if count > 0:
        audit(db, request, "submission_approved_all", f"approved {count} submissions", user=admin)
        db.commit()
    return RedirectResponse("/admin", status_code=303)


@app.post("/admin/submissions/{sub_id}/approve")
async def admin_approve(sub_id: int, request: Request, db: Session = Depends(get_db)):
    admin = require_admin(request, db)
    sub = db.get(Submission, sub_id)
    if not sub:
        raise HTTPException(status_code=404)
    if sub.status != "approved":
        sub.status = "approved"
        sub.decided_at = utcnow()
        sub.rejection_reason = None
        submitter = db.get(User, sub.user_id)
        if submitter:
            await notifications.notify_submission_status(db, submitter, "approved")
        audit(db, request, "submission_approved", f"sub #{sub_id}", user=admin)
        db.commit()
    return RedirectResponse("/admin", status_code=303)


@app.post("/admin/submissions/{sub_id}/reject")
async def admin_reject(
    sub_id: int,
    request: Request,
    reason: str = Form(""),
    db: Session = Depends(get_db),
):
    admin = require_admin(request, db)
    sub = db.get(Submission, sub_id)
    if not sub:
        raise HTTPException(status_code=404)
    sub.status = "rejected"
    sub.decided_at = utcnow()
    sub.rejection_reason = (reason or "").strip()[:500] or None
    submitter = db.get(User, sub.user_id)
    if submitter:
        await notifications.notify_submission_status(db, submitter, "rejected", sub.rejection_reason)
    audit(db, request, "submission_rejected", f"sub #{sub_id} reason={sub.rejection_reason or '-'}", user=admin)
    db.commit()
    return RedirectResponse("/admin", status_code=303)


@app.get("/admin/leaderboard.csv")
def admin_export_csv(request: Request, db: Session = Depends(get_db)):
    require_admin(request, db)
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["rank", "name", "email", "phone", "department", "role", "approved_reviews"])
    for i, r in enumerate(leaderboard_rows(db), start=1):
        writer.writerow([i, r["name"], r["email"] or "", r["phone"] or "", r["department"] or "", r["role"] or "", r["approved"]])
    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=leaderboard.csv"},
    )


# --------------------------- Health & meta -------------------------------

@app.get("/healthz")
def healthz():
    return {"ok": True, "admins": sorted(config.ADMIN_EMAILS)}


@app.exception_handler(404)
def not_found(request: Request, exc):
    # Generic 404 — never reveal whether an admin route exists.
    accept = request.headers.get("accept", "")
    if "text/html" in accept:
        return HTMLResponse(
            "<!doctype html><meta name=viewport content='width=device-width,initial-scale=1'>"
            "<title>Not found</title>"
            "<body style='font-family:system-ui;background:#0e1419;color:#e6edf2;display:grid;place-items:center;height:100vh;margin:0'>"
            "<div style='text-align:center'><h1 style='font-size:64px;margin:0;color:#f97316'>404</h1>"
            "<p>The page you're looking for doesn't exist.</p>"
            "<a href='/' style='color:#fb923c'>Go home</a></div></body>",
            status_code=404,
        )
    return JSONResponse({"detail": "Not found"}, status_code=404)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
