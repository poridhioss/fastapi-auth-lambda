"""JWT helpers for Lab 4.

The architecture follows the reference: a Lambda authorizer at the API
Gateway edge verifies the access token before the request reaches the
FastAPI Lambda. Inside the FastAPI Lambda, the email/user_id is read from
the principal header (set by the authorizer) rather than re-decoding the
token - which is faster and avoids a second HMAC compute per request.

We still need this module for two things:
  1. minting access + refresh tokens on signup/login/refresh
  2. verifying refresh tokens inside the FastAPI Lambda (refresh isn't
     routed through the authorizer)

Same secret + algorithm + 32-byte floor as Labs 1-3.

PRODUCTION NOTES:

* Hardcoded `_ALGORITHM = "HS256"`. Never read this from an env var: a
  misconfigured env could downgrade to "none" (no signature).
* Module import hard-fails if `JWT_SECRET` is missing, the placeholder
  value, or shorter than 32 bytes (RFC 7518 minimum for HS256).
* `_ALLOWED_TYPES` is the only source of truth for which `type` claim
  values we accept; any other value is rejected.
"""

import os
import sys
import uuid
from datetime import datetime, timedelta, timezone
from typing import Literal

# Flat-zip layout: keep absolute imports working on Lambda.
sys.path.insert(0, os.path.dirname(__file__))

import jwt  # noqa: E402

# Hardcoded algorithm allowlist. Never read this from an env var: a
# misconfigured env could downgrade to "none" (no signature).
_ALGORITHM = "HS256"

_SECRET = os.getenv("JWT_SECRET")
_PLACEHOLDER_SECRET = "replace-with-a-long-random-string"
if not _SECRET:
    raise RuntimeError(
        "JWT_SECRET is not set. On Lambda, set it in Configuration > "
        "Environment variables. Locally: export JWT_SECRET=... before running."
    )
if _SECRET == _PLACEHOLDER_SECRET:
    raise RuntimeError(
        "JWT_SECRET is still the placeholder value. Generate a real one with: "
        "python -c \"import secrets; print(secrets.token_urlsafe(48))\""
    )
if len(_SECRET.encode("utf-8")) < 32:
    raise RuntimeError(
        f"JWT_SECRET is too short ({len(_SECRET)} chars). RFC 7518 requires "
        "at least 32 bytes for HS256. Generate one with: "
        "python -c \"import secrets; print(secrets.token_urlsafe(48))\""
    )

# What `type` claim values we will sign + verify. Anything else is rejected.
_ALLOWED_TYPES = frozenset({"access", "refresh"})


class TokenError(Exception):
    """Raised when a token is invalid or expired."""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _encode(payload: dict) -> str:
    return jwt.encode(payload, _SECRET, algorithm=_ALGORITHM)


def create_access_token(user_id: str) -> str:
    """Short-lived access token. JWT `sub` = user_id (UUID, not email).

    This matches the reference architecture where users.PK = user_id and
    email is a GSI key. Using user_id (not email) means a future email
    change does not invalidate issued tokens.
    """
    minutes = int(os.getenv("ACCESS_TTL_MIN", "5"))
    payload = {
        "sub": str(user_id),
        "type": "access",
        "jti": str(uuid.uuid4()),  # unique id -> never collide across mints
        "iat": _now(),
        "exp": _now() + timedelta(minutes=minutes),
    }
    return _encode(payload)


def create_refresh_token(user_id: str) -> str:
    """Long-lived refresh token. Same shape, longer TTL, different 'type'.

    `jti` is REQUIRED on refresh tokens: the session row PK is the refresh
    JWT itself, and a rotation only works if the new token's bytes differ
    from the old one's (otherwise put_session overwrites the just-deleted
    row, and replay looks like success). PyJWT collapses `iat` to whole
    seconds, so two mints in the same second are otherwise identical.
    """
    days = int(os.getenv("REFRESH_TTL_DAYS", "7"))
    payload = {
        "sub": str(user_id),
        "type": "refresh",
        "jti": str(uuid.uuid4()),  # guarantees unique tokens per mint
        "iat": _now(),
        "exp": _now() + timedelta(days=days),
    }
    return _encode(payload)


def decode_token(token: str, expected_type: Literal["access", "refresh"]) -> dict:
    """Verify a token's signature and expiry; return its claims.

    Raises TokenError if signature is invalid, token is expired, or
    `type` does not match `expected_type`.

    `expected_type` is enforced at the type-system level via Literal, but
    we also validate it's in our allowlist at runtime to defend against
    bogus internal callers.
    """
    if expected_type not in _ALLOWED_TYPES:
        raise TokenError(f"internal error: invalid expected_type={expected_type!r}")
    if not isinstance(token, str) or not token:
        raise TokenError("Token is empty")

    try:
        claims = jwt.decode(
            token,
            _SECRET,
            algorithms=[_ALGORITHM],
            leeway=10,  # tolerate small clock drift
        )
    except jwt.ExpiredSignatureError:
        raise TokenError("Token expired")
    except jwt.InvalidTokenError:
        raise TokenError("Invalid token")

    if not isinstance(claims, dict):
        raise TokenError("Invalid token claims")

    sub = claims.get("sub")
    if not isinstance(sub, str) or not sub:
        raise TokenError("Invalid sub claim")

    if claims.get("type") != expected_type:
        raise TokenError(f"Expected {expected_type} token, got {claims.get('type')}")

    return claims