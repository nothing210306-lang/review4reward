from __future__ import annotations

import urllib.parse
from typing import Optional, Tuple

import httpx

import config


def build_authorization_url(state: str, base_url: str) -> str:
    redirect_uri = base_url.rstrip("/") + config.GOOGLE_REDIRECT_PATH
    params = {
        "client_id": config.GOOGLE_CLIENT_ID,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "access_type": "online",
        "prompt": "select_account",
    }
    return "https://accounts.google.com/o/oauth2/v2/auth?" + urllib.parse.urlencode(params)


async def exchange_code_for_user(code: str, base_url: str) -> Tuple[str, str, Optional[str]]:
    """Exchange the authorization code for verified (email, name, picture).

    Verifies tokens via Google's token endpoint; raises on any failure.
    Returns (email, full_name, picture_url).
    """
    redirect_uri = base_url.rstrip("/") + config.GOOGLE_REDIRECT_PATH
    async with httpx.AsyncClient(timeout=20) as client:
        token_resp = await client.post(
            "https://oauth2.googleapis.com/token",
            data={
                "code": code,
                "client_id": config.GOOGLE_CLIENT_ID,
                "client_secret": config.GOOGLE_CLIENT_SECRET,
                "redirect_uri": redirect_uri,
                "grant_type": "authorization_code",
            },
        )
        token_resp.raise_for_status()
        tokens = token_resp.json()
        id_token = tokens.get("id_token")
        if not id_token:
            raise RuntimeError("Google did not return an ID token.")

        # Verify the ID token with Google (signature, expiry, audience).
        info_resp = await client.get(
            "https://oauth2.googleapis.com/tokeninfo",
            params={"id_token": id_token},
        )
        info_resp.raise_for_status()
        info = info_resp.json()

    if info.get("aud") != config.GOOGLE_CLIENT_ID:
        raise RuntimeError("ID token audience mismatch.")
    if info.get("email_verified") not in ("true", True):
        raise RuntimeError("Google email is not verified.")
    email = (info.get("email") or "").strip().lower()
    if not email:
        raise RuntimeError("Google response missing email.")
    name = info.get("name") or email.split("@")[0]
    picture = info.get("picture")
    return email, name, picture
