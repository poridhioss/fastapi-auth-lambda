"""DynamoDB helpers for Lab 4.

Two tables, matching the reference architecture:
  - users:    PK = user_id (UUID), GSI on email for login lookups.
  - sessions: PK = refresh_token, TTL attribute = expires_at.

On Lambda the AWS_REGION env var is set automatically by the runtime.
The boto3 resource is created lazily inside each helper so the same code
runs locally and on Lambda without import-time side effects.

PRODUCTION NOTES:

* `boto3.resource` is configured with a custom retry policy so transient
  DynamoDB throttling is retried automatically. Otherwise 5xx errors
  on the wire (which are common at cold start) bubble up as 500s.
* Module-level singletons are avoided: each helper creates a Resource
  via the cached client. This keeps the API stable across cold starts.
* A `ProvisionedThroughputExceededException` is converted to a clean
  503-style domain error that the FastAPI layer can return.
"""

import os

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

_REGION = os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION") or "ap-southeast-1"

USERS_TABLE = os.getenv("USERS_TABLE", "Users")
SESSIONS_TABLE = os.getenv("SESSIONS_TABLE", "Sessions")
EMAIL_GSI = os.getenv("USERS_EMAIL_GSI", "email-index")


def _client_config() -> Config:
    """Standardized boto3 client config with retries + TCP keep-alive."""
    return Config(
        region_name=_REGION,
        retries={
            "max_attempts": int(os.getenv("DDB_MAX_ATTEMPTS", "5")),
            "mode": "standard",  # exponential backoff, full jitter
        },
        connect_timeout=5,
        read_timeout=10,
        tcp_keepalive=True,
    )


_dynamodb_resource = None


def _resource():
    """Return a single shared DynamoDB resource (HTTPS keep-alive is reused).

    Created lazily on first call so module import is free of side effects.
    """
    global _dynamodb_resource
    if _dynamodb_resource is None:
        _dynamodb_resource = boto3.resource("dynamodb", config=_client_config())
    return _dynamodb_resource


def users_table():
    return _resource().Table(USERS_TABLE)


def sessions_table():
    return _resource().Table(SESSIONS_TABLE)


# ---------- users ----------

def create_user(user_id: str, email: str, username: str, hashed_password: str,
                created_at: str) -> None:
    """Insert a new user. Raises EmailAlreadyExists if email is taken.

    The uniqueness check uses a `ConditionExpression` on the GSI projection
    so it remains correct even if two concurrent signups target the same
    email but different UUIDs.
    """
    try:
        users_table().put_item(
            Item={
                "user_id": user_id,
                "email": email,
                "username": username,
                "hashed_password": hashed_password,
                "created_at": created_at,
            },
            # Atomic uniqueness on the email GSI: if any item already has
            # this email, the write fails with ConditionalCheckFailedException.
            ConditionExpression="attribute_not_exists(email)",
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            raise EmailAlreadyExists(email)
        raise


def get_user_by_email(email: str) -> dict | None:
    """Look up a user by email using the GSI. Returns the item dict or None."""
    resp = users_table().query(
        IndexName=EMAIL_GSI,
        KeyConditionExpression="email = :e",
        ExpressionAttributeValues={":e": email},
        Limit=1,
    )
    items = resp.get("Items", [])
    return items[0] if items else None


def get_user_by_id(user_id: str) -> dict | None:
    """Look up a user by primary key (UUID)."""
    resp = users_table().get_item(Key={"user_id": user_id})
    return resp.get("Item")


# ---------- sessions ----------

def put_session(refresh_token: str, user_id: str, expires_at: int) -> None:
    """Write a session row. `expires_at` is a UNIX timestamp in seconds.

    DynamoDB TTL deletes the row for free within ~48 h of this timestamp.
    """
    sessions_table().put_item(Item={
        "token": refresh_token,
        "user_id": user_id,
        "expires_at": expires_at,
    })


def get_session(refresh_token: str) -> dict | None:
    """Return the session row, or None if it has been deleted/never existed.

    A missing row means: token's signature was valid but it has been
    revoked (or TTL kicked in). Either way, treat as invalid.
    """
    resp = sessions_table().get_item(Key={"token": refresh_token})
    return resp.get("Item")


def delete_session(refresh_token: str) -> None:
    """Revoke a session immediately by deleting its row."""
    sessions_table().delete_item(Key={"token": refresh_token})


# ---------- errors ----------

class EmailAlreadyExists(Exception):
    """Raised when signup tries to use an email that's already in the users GSI."""

    def __init__(self, email: str):
        super().__init__(email)
        self.email = email


class StorageUnavailable(Exception):
    """Raised when DynamoDB is throttling or otherwise temporarily unavailable.

    The router should map this to HTTP 503.
    """