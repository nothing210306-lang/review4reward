"""Server-side verification of Firebase Auth ID tokens (for phone sign-in).

Uses Google's public x509 certificates for the `securetoken@system.gserviceaccount.com`
issuer — no Firebase Admin SDK or service-account JSON required. Certificates are
cached in memory and refreshed when they expire (Google returns `Cache-Control` /
`Expires` headers).
"""
from __future__ import annotations

import time
from typing import Any, Dict, Optional

import httpx
import jwt

CERT_URL = "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com"

_certs_cache: Dict[str, Any] = {"pems": None, "expires_at": 0.0}


async def _get_public_keys() -> Dict[str, str]:
    now = time.time()
    if _certs_cache["pems"] is not None and now < _certs_cache["expires_at"]:
        return _certs_cache["pems"]

    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(CERT_URL)
        r.raise_for_status()
        pems = r.json()
        # Honour the Expires/Cache-Control header; default 1h.
        expires = now + 3600
        cc = r.headers.get("cache-control", "")
        for part in cc.split(","):
            part = part.strip().lower()
            if part.startswith("max-age="):
                try:
                    expires = now + int(part.split("=", 1)[1])
                except ValueError:
                    pass
        _certs_cache["pems"] = pems
        _certs_cache["expires_at"] = expires
        return pems


class FirebaseTokenError(Exception):
    pass


async def verify_id_token(id_token: str, project_id: str) -> Dict[str, Any]:
    """Verify a Firebase Auth ID token and return its claims.

    Raises FirebaseTokenError on any validation failure.
    """
    if not id_token or not project_id:
        raise FirebaseTokenError("Missing token or project ID")

    pems = await _get_public_keys()

    # Read the unverified header to pick the correct signing certificate by kid.
    try:
        header = jwt.get_unverified_header(id_token)
    except Exception as exc:  # noqa: BLE001
        raise FirebaseTokenError(f"Malformed token header: {exc}") from exc
    kid = header.get("kid")
    alg = header.get("alg")
    if alg != "RS256":
        raise FirebaseTokenError(f"Unsupported algorithm: {alg}")
    if not kid or kid not in pems:
        # Fall back to trying every key if the kid isn't in the current cert set
        # (e.g. Google rotated them); refetch on the next call.
        pem = None
    else:
        pem = pems[kid]

    candidate_pems = [pem] if pem else list(pems.values())

    last_error: Optional[Exception] = None
    for candidate in candidate_pems:
        try:
            claims = jwt.decode(
                id_token,
                candidate,
                algorithms=["RS256"],
                audience=project_id,
                issuer=f"https://securetoken.google.com/{project_id}",
                options={"require": ["exp", "iat", "sub", "aud", "iss"]},
            )
            sub = claims.get("sub", "")
            if not sub or not isinstance(sub, str):
                raise FirebaseTokenError("Token missing subject")
            # Firebase guarantees sub is non-empty and <= 256 chars.
            if len(sub) > 256:
                raise FirebaseTokenError("Token subject too long")
            return claims
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            # Try the next candidate key (only relevant when kid was missing).
            continue

    raise FirebaseTokenError(f"Token verification failed: {last_error}")
