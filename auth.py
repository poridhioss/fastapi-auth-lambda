"""FastAPI router for Lab 4.

Four routes, matching the reference architecture:
  POST /signup   - create user, mint pair, write session
  POST /login    - verify bcrypt, mint pair, write session
  POST /refresh  - verify signature + session row, rotate
  GET  /me       - read user_id from principal header, fetch user

The reference uses Lambda authorizer at the edge, so /me does NOT need
to re-verify the JWT. Instead the authorizer passes the user_id as a
header (`x-principal-user-id`) which this router trusts. That makes /me
the cheapest route in the system.
"""

import os
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Header, HTTPException, Request, status

from botocore.exceptions import ClientError

# Flat-zip layout: ensure the zip root is on sys.path so absolute imports
# work without the `app.` prefix on Lambda.
sys.path.insert(0, os.path.dirname(__file__))

from db import (
    EmailAlreadyExists,
    StorageUnavailable,
    create_user,
    delete_session,
    get_session,
    get_user_by_email,
    get_user_by_id,
    put_session,
)
from hashing import hash_password, verify_password
from jwt_utils import (
    TokenError,
    create_access_token,
    create_refresh_token,
    decode_token,
)
from schemas import (
    LoginRequest,
    MeResponse,
    RefreshRequest,
    SignupRequest,
    TokenPair,
)

router = APIRouter()

# Authorizer passes the verified user_id on this header. If the header is
# missing on a protected route, that's a wiring bug - 401.
PRINCIPAL_HEADER = "x-user_id"

# Throttle / transient DynamoDB errors should surface as 503, not 500.
_TROUBLE_CODES = {
    "ProvisionedThroughputExceededException",
    "ThrottlingException",
    "RequestLimitExceeded",
    "ServiceUnavailable",
    "InternalServerError",  # DDB-side internal, retryable
}


def _handle_ddb_errors(route_fn):
    """Decorator: convert DDB transient failures into clean 503 responses.

    Why: boto3 raises ClientError for both perma-failures (validation) and
    transient failures (throttling, timeouts). Without this decorator,
    every DDB hiccup would surface as a 500 to the client. 503 is a
    retryable response and triggers CloudWatch alarms on the right metric.
    """
    import functools
    from fastapi import HTTPException, status as http_status

    @functools.wraps(route_fn)
    def wrapper(*args, **kwargs):
        try:
            return route_fn(*args, **kwargs)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code in _TROUBLE_CODES:
                raise HTTPException(
                    status_code=http_status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Storage temporarily unavailable, retry",
                )
            raise
        except StorageUnavailable:
            raise HTTPException(
                status_code=http_status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Storage temporarily unavailable, retry",
            )

    return wrapper


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _refresh_ttl_seconds() -> int:
    return int(os.getenv("REFRESH_TTL_DAYS", "7")) * 86400


def _mint_and_persist(user_id: str) -> TokenPair:
    """Mint an access + refresh token pair, write the session row.

    The session row is what makes /refresh stateless on the *JWT* side
    but revocable on the *DB* side. Delete the row to revoke immediately.
    """
    access = create_access_token(user_id)
    refresh = create_refresh_token(user_id)
    expires_at = int(time.time()) + _refresh_ttl_seconds()
    put_session(refresh, user_id, expires_at)
    return TokenPair(access_token=access, refresh_token=refresh, token_type="bearer")


# ---------- POST /signup ----------

@router.post("/signup", status_code=status.HTTP_201_CREATED, response_model=TokenPair)
@_handle_ddb_errors
def signup(payload: SignupRequest):
    """Create a user and return a token pair.

    Email uniqueness is enforced atomically by DynamoDB's ConditionExpression
    on the email GSI - two simultaneous signups with the same email cannot
    both succeed.
    """
    email = payload.email.lower().strip()
    if get_user_by_email(email) is not None:
        # Quick pre-check to give a clean 409 without writing first. The
        # ConditionExpression below is still the source of truth under
        # concurrent writes.
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail="Email already registered")

    user_id = str(uuid.uuid4())
    try:
        create_user(
            user_id=user_id,
            email=email,
            username=payload.username,
            hashed_password=hash_password(payload.password),
            created_at=_now().isoformat(),
        )
    except EmailAlreadyExists:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail="Email already registered")

    return _mint_and_persist(user_id)


# ---------- POST /login ----------

@router.post("/login", response_model=TokenPair)
@_handle_ddb_errors
def login(payload: LoginRequest):
    """Verify credentials, return a fresh token pair, write a new session row."""
    email = payload.email.lower().strip()
    user = get_user_by_email(email)
    # Same error message for "no such email" and "wrong password" - prevents
    # email enumeration attacks.
    if user is None or not verify_password(payload.password, user["hashed_password"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid email or password")
    return _mint_and_persist(user["user_id"])


# ---------- POST /refresh ----------

@router.post("/refresh", response_model=TokenPair)
@_handle_ddb_errors
def refresh(payload: RefreshRequest):
    """Exchange a valid refresh token for a new pair.

    Two checks:
      1. JWT signature + expiry (cryptographic validity)
      2. Session row exists in DynamoDB (server-side revocation)
    Both must pass. If either fails, the request is rejected.
    """
    try:
        claims = decode_token(payload.refresh_token, expected_type="refresh")
    except TokenError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc))

    session = get_session(payload.refresh_token)
    if session is None:
        # Signature is valid but the session was revoked (row deleted) or
        # TTL kicked in. Either way, deny.
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Session revoked")

    # Rotate: delete the old session row, issue a new pair + new row.
    # This is "refresh token rotation" - if the old token is ever used
    # again, the session lookup fails and we know it was leaked.
    #
    # Order matters: DELETE the old row BEFORE minting the new one. Tokens
    # carry a unique `jti` (see jwt_utils.create_refresh_token), so the new
    # row's PK (the new JWT) differs from the old. Doing delete-then-mint
    # guarantees a brief window where neither row exists if put_session
    # fails - which is correct: better to log out the user than to leave
    # the old token reusable.
    delete_session(payload.refresh_token)
    return _mint_and_persist(claims["sub"])


# ---------- GET /me ----------

@router.get("/me", response_model=MeResponse)
@_handle_ddb_errors
def me(request: Request,
        x_principal_user_id: str | None = Header(default=None, alias=PRINCIPAL_HEADER)):
    """Return the currently authenticated user's profile.

    `x_principal_user_id` is set by the Lambda authorizer AFTER it
    verified the JWT signature. We do not re-verify here - that's the
    whole point of doing auth at the edge.
    """
    if not x_principal_user_id:
        # Should never happen if API Gateway is wired correctly: the
        # authorizer is supposed to inject this header on every /me call.
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Missing principal")

    user = get_user_by_id(x_principal_user_id)
    if user is None:
        # The token was valid but the user has been deleted since.
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="User no longer exists")

    return MeResponse(
        user_id=user["user_id"],
        email=user["email"],
        username=user["username"],
        created_at=user.get("created_at"),
    )