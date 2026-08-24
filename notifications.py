from __future__ import annotations

import logging
from typing import Optional

import httpx
from sqlalchemy.orm import Session

import config
from db import Notification, User, utcnow

log = logging.getLogger("notifications")


# ----------------------------- Email (Resend) ------------------------------

async def send_email(to_email: str, subject: str, html: str) -> bool:
    if not config.EMAIL_ENABLED:
        log.warning("DEV EMAIL -> to=%s subject=%s\n%s", to_email, subject, html)
        return False
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            r = await client.post(
                "https://api.resend.com/emails",
                headers={
                    "Authorization": f"Bearer {config.RESEND_API_KEY}",
                    "Content-Type": "application/json",
                },
                json={
                    "from": config.EMAIL_FROM,
                    "to": to_email,
                    "subject": subject,
                    "html": html,
                },
            )
        if r.status_code >= 300:
            log.error("Resend email failed %s: %s", r.status_code, r.text[:500])
            return False
        log.info("Resend email sent to %s: %s", to_email, r.text[:200])
        return True
    except Exception as exc:  # noqa: BLE001
        log.exception("Resend email exception: %s", exc)
        return False


# ------------------------------- SMS (Twilio) ------------------------------

async def send_sms(to_phone: str, body: str) -> bool:
    if not config.SMS_ENABLED:
        log.warning("DEV SMS -> to=%s body=%s", to_phone, body)
        return False
    try:
        from twilio.rest import Client

        client = Client(config.TWILIO_ACCOUNT_SID, config.TWILIO_AUTH_TOKEN)
        client.messages.create(to=to_phone, from_=config.TWILIO_FROM_NUMBER, body=body)
        return True
    except Exception as exc:  # noqa: BLE001
        log.exception("Twilio SMS failed: %s", exc)
        return False


# --------------------------- In-app notification ---------------------------

def record_inapp(db: Session, user_id: int, kind: str, body: str) -> None:
    db.add(Notification(user_id=user_id, channel="inapp", kind=kind, body=body))


# ----------------------------- High-level API ------------------------------

MESSAGES = {
    "under_verification": (
        "We've received your review screenshot — it's now under verification. "
        "You'll be notified as soon as it's reviewed.",
        "Your review screenshot is under verification",
    ),
    "approved": (
        "Your review has been approved and now counts toward your leaderboard score. Thank you!",
        "Your review has been approved",
    ),
    "rejected": (
        "Your review submission was not approved{reason}. Please reach out to the admin team if you think this is a mistake.",
        "Your review submission was not approved",
    ),
}


async def notify_submission_status(
    db: Session,
    user: User,
    kind: str,
    rejection_reason: Optional[str] = None,
) -> None:
    """Send a notification through the channel that matches how the user signed up.

    Google users get email; phone users get SMS. Every message is ALSO persisted
    as an in-app notification so the UI can show a notification center regardless
    of provider delivery (and so dev-mode still surfaces the message).
    """
    body, subject = MESSAGES[kind]
    if kind == "rejected":
        reason_part = f": {rejection_reason}" if rejection_reason else ""
        body = body.format(reason=reason_part)
        subject = f"{subject}{reason_part}"

    record_inapp(db, user.id, kind, body)

    if user.provider == "google" and user.email:
        await send_email(
            user.email,
            subject,
            f"<div style='font-family:system-ui,sans-serif'>"
            f"<h2>{subject}</h2><p>{body}</p></div>",
        )
    elif user.provider == "phone" and user.phone:
        await send_sms(user.phone, f"Review for Reward: {body}")
