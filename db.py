from __future__ import annotations

import datetime as dt
import os
from sqlalchemy import (
    Column,
    Integer,
    String,
    DateTime,
    Text,
    ForeignKey,
    UniqueConstraint,
    Index,
    create_engine,
)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker, Session

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def _database_url() -> str:
    url = os.environ.get("DATABASE_URL", "").strip()
    if url:
        # Normalize scheme; we'll append pgbouncer as a connect_args option
        # rather than a DSN query param (libpq rejects unknown params).
        if "?" in url:
            url, _, _query = url.partition("?")
        if url.startswith("postgres://"):
            url = url.replace("postgres://", "postgresql+pg8000://", 1)
        elif url.startswith("postgresql+psycopg2://"):
            url = url.replace("postgresql+psycopg2://", "postgresql+pg8000://", 1)
        elif url.startswith("postgresql://"):
            url = "postgresql+pg8000://" + url[len("postgresql://"):]
        return url
    return f"sqlite:///{os.path.join(BASE_DIR, 'app.db')}"


DATABASE_URL = _database_url()
USING_POSTGRES = DATABASE_URL.startswith("postgresql")

Base = declarative_base()


def utcnow() -> dt.datetime:
    # Naive UTC. Stored consistently on both SQLite and Postgres, and avoids
    # mixed tz-aware/naive comparisons when rows are read back.
    return dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    # Identity is EITHER a verified Google email OR a verified E.164 phone number.
    # Never both on the same record; the provider field distinguishes them.
    provider = Column(String(16), nullable=False)  # "google" | "phone"
    email = Column(String(320), unique=True, nullable=True)  # google only
    phone = Column(String(32), unique=True, nullable=True)  # phone only
    full_name = Column(String(200), nullable=True)
    department = Column(String(200), nullable=True)
    role = Column(String(200), nullable=True)
    profile_complete = Column(Integer, default=0, nullable=False)
    is_admin = Column(Integer, default=0, nullable=False)  # derived at login, not trusted from client
    created_at = Column(DateTime, default=utcnow, nullable=False)
    last_login_at = Column(DateTime, nullable=True)

    submissions = relationship("Submission", back_populates="user", cascade="all,delete")


class Submission(Base):
    __tablename__ = "submissions"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    status = Column(String(32), default="pending", nullable=False, index=True)
    # pending | under_verification | approved | rejected
    customer_name = Column(String(200), nullable=True)
    notes = Column(Text, nullable=True)
    image_url = Column(String(1024), nullable=False)
    image_storage = Column(String(16), default="disk", nullable=False)  # disk | blob
    dhash = Column(String(64), nullable=False, index=True)  # 64-bit dhash as hex string
    rejection_reason = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utcnow, nullable=False, index=True)
    decided_at = Column(DateTime, nullable=True)

    user = relationship("User", back_populates="submissions")


class OtpChallenge(Base):
    __tablename__ = "otp_challenges"
    id = Column(Integer, primary_key=True)
    phone = Column(String(32), nullable=False, index=True)
    code_hash = Column(String(128), nullable=False)
    expires_at = Column(DateTime, nullable=False)
    consumed = Column(Integer, default=0, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    ip = Column(String(64), nullable=True)


class Notification(Base):
    __tablename__ = "notifications"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    channel = Column(String(16), nullable=False)  # email | sms | inapp
    kind = Column(String(40), nullable=False)  # under_verification | approved | rejected
    body = Column(Text, nullable=False)
    read = Column(Integer, default=0, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)


class AuditLog(Base):
    __tablename__ = "audit_log"
    id = Column(Integer, primary_key=True)
    ts = Column(DateTime, default=utcnow, nullable=False, index=True)
    actor_user_id = Column(Integer, nullable=True)
    actor_label = Column(String(320), nullable=True)
    action = Column(String(64), nullable=False)
    detail = Column(Text, nullable=True)
    ip = Column(String(64), nullable=True)


Index("ix_otp_phone_created", OtpChallenge.phone, OtpChallenge.created_at)

_engine_kwargs = {"future": True, "pool_pre_ping": True}
if DATABASE_URL.startswith("sqlite"):
    _engine_kwargs["connect_args"] = {"check_same_thread": False}
else:
    # Postgres with pg8000 (pure-Python driver, works on Vercel serverless).
    # pg8000 does not support psycopg2-specific connect_args like options/connect_timeout.
    _engine_kwargs["pool_recycle"] = 300
    from sqlalchemy.pool import NullPool
    # For serverless functions a NullPool is safer (no shared state across
    # invocations). Locally you can remove this for pooling.
    if os.environ.get("VERCEL") or os.environ.get("SERVERLESS"):
        _engine_kwargs["poolclass"] = NullPool

engine = create_engine(DATABASE_URL, **_engine_kwargs)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


def init_db() -> None:
    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
