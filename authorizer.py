"""Lambda authorizer for Lab 4.

Reference architecture says: a Lambda authorizer sits at the API Gateway
edge and verifies the access token *before* the request reaches the
backend. This module is that authorizer.

API Gateway HTTP API v2 invokes this Lambda with a payload like:

    {
      "version": "2.0",
      "type": "REQUEST",
      "rawPath": "/me",
      "headers": { "authorization": "Bearer <token>", ... },
      "requestContext": { "http": { "method": "GET", "path": "/me", ... } },
      "routeKey": "$default"
    }

It expects us to return an IAM-style policy:

    {
      "isAuthorized": true,
      "context": { "user_id": "<uuid>", "email": "..." }
    }

The `context` object becomes available to the backend Lambda as the
`x-principal-user-id` (and friends) request headers - that's how
`auth.py` learns who the user is without re-verifying the JWT.

We cache verified tokens in module scope (a tiny in-memory LRU) so a
warm authorizer doesn't re-HMAC the same token on every call.

PRODUCTION NOTES:

* Payload format: 2.0 (the console default for HTTP APIs).
* Simple responses: enabled. Returns `{"isAuthorized": bool, "context": {...}}`.
* Identity source: `$request.header.Authorization`.
* IMPORTANT: per the AWS docs
  https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-lambda-authorizer.html
  "If you specify identity sources, clients must include them in the request.
  If the client's request doesn't include the identity sources, API Gateway
  doesn't invoke your Lambda authorizer, and the client receives a 401 error."
  This means /login, /signup, /health that DON'T send an Authorization header
  will be blocked at the edge. The README documents this constraint.
"""

from __future__ import annotations

import logging
import os
import sys
import time
from collections import OrderedDict
from typing import Any

# Flat-zip layout: the Lambda zip contains the contents of app/ at the root,
# so we import jwt_utils without the `app.` prefix. Adding the zip root to
# sys.path keeps this working when invoked locally too.
sys.path.insert(0, os.path.dirname(__file__))

from jwt_utils import TokenError, decode_token  # noqa: E402

# Configure structured logging once per cold start. The Lambda runtime
# already adds `requestId` to every record via the standard log group.
logger = logging.getLogger()
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(
        fmt="%(asctime)s %(levelname)s %(name)s %(message)s",
    ))
    logger.addHandler(handler)
logger.setLevel(os.getenv("LOG_LEVEL", "INFO"))

# Module-level cache: token string -> (verified_user_id, expires_at_epoch).
# Bounded so a busy server can't grow this without bound. Each entry is
# the size of a short string + a small dict - safe at a few thousand entries.
_CACHE_LIMIT = int(os.getenv("AUTHORIZER_CACHE_SIZE", "256"))
_cache: "OrderedDict[str, tuple[str, float]]" = OrderedDict()

# Tokens that can't possibly be valid have a maximum reasonable size.
# Real JWTs are well under 4 KB; anything bigger is a probe.
_MAX_TOKEN_LEN = int(os.getenv("AUTHORIZER_MAX_TOKEN_LEN", "4096"))


def _cache_get(token: str) -> str | None:
    """Return cached user_id if present and not expired; else None."""
    entry = _cache.get(token)
    if entry is None:
        return None
    user_id, expires_at = entry
    if expires_at <= time.time():
        _cache.pop(token, None)
        return None
    # LRU touch
    _cache.move_to_end(token)
    return user_id


def _cache_put(token: str, user_id: str, expires_at: float) -> None:
    _cache[token] = (user_id, expires_at)
    _cache.move_to_end(token)
    while len(_cache) > _CACHE_LIMIT:
        _cache.popitem(last=False)


def _extract_bearer(event: dict) -> str | None:
    """Pull a Bearer token out of the v2 event headers.

    Returns None if absent or malformed. Does NOT raise - any decode error
    becomes a clean deny.
    """
    headers = event.get("headers") or {}
    if not isinstance(headers, dict):
        return None
    # HTTP API v2 lowercases header names, but be tolerant of either casing.
    auth = headers.get("authorization") or headers.get("Authorization")
    if not auth or not isinstance(auth, str):
        return None
    parts = auth.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    token = parts[1].strip()
    if not token or len(token) > _MAX_TOKEN_LEN:
        return None
    return token


def _deny(reason: str) -> dict:
    """Standard deny response. Logs the reason at INFO so 401 spikes are visible."""
    logger.info("deny: %s", reason)
    return {"isAuthorized": False, "context": {"reason": reason}}


def lambda_handler(event: dict, context: Any) -> dict:
    """API Gateway HTTP API v2 authorizer entry point.

    Returns the v2 simple-response policy shape:
        {"isAuthorized": bool, "context": {...}}
    If isAuthorized is False, API Gateway short-circuits the request with a
    401 and never invokes the backend.

    The handler MUST NOT raise. Any uncaught exception causes API Gateway
    to return 500 to the client (not a clean 401), which is harder to
    diagnose and shows up as user-facing errors. We catch broadly.
    """
    try:
        token = _extract_bearer(event)
        if not token:
            return _deny("Missing or malformed Bearer token")

        user_id = _cache_get(token)
        if user_id is None:
            try:
                claims = decode_token(token, expected_type="access")
            except TokenError as exc:
                return _deny(f"Invalid token: {exc}")
            except Exception as exc:  # noqa: BLE001 - last-resort safety net
                # Never raise out of an authorizer.
                logger.exception("unexpected JWT decode error")
                return _deny(f"Token validation failed: {exc}")
            user_id = claims["sub"]
            if not isinstance(user_id, str) or not user_id:
                return _deny("Token missing or invalid sub claim")
            # Cache until the token itself expires (with a 10s safety margin
            # matching the leeway in decode_token).
            _cache_put(token, user_id, claims["exp"] - 10)

        logger.debug("allow user_id=%s route=%s", user_id, event.get("routeKey"))
        # API Gateway injects each context field as a header named
        # x-user_id on the backend invocation. The auth router
        # reads `x-user_id`.
        return {
            "isAuthorized": True,
            "context": {
                "user_id": user_id,
            },
        }
    except Exception as exc:  # noqa: BLE001
        # Last-resort safety net. Returning 500 from an authorizer is a
        # very bad failure mode; we degrade to deny instead.
        logger.exception("unhandled exception in authorizer")
        return {"isAuthorized": False, "context": {"reason": f"authorizer error: {exc}"}}