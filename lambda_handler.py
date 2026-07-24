"""Mangum adapter for the FastAPI app.

`handler` is the symbol API Gateway (HTTP API v2) calls when the
configured route fires. Mangum translates the API Gateway v2 event
shape into an ASGI scope that FastAPI understands.

Reference: https://mangum.fastapiexpert.com/

The zip we deploy to Lambda contains the contents of `app/` flattened
into the zip root (no `app/` directory), so we use absolute imports
without the `app.` prefix. This avoids `ImportError: attempted relative
import with no known parent package` on Lambda.
"""

import json
import logging
import os
import sys

# Make sure the zip root is on the import path. Lambda sets cwd to /var/task,
# but adding it explicitly is harmless on Lambda and required locally.
sys.path.insert(0, os.path.dirname(__file__))

from mangum import Mangum  # noqa: E402
from main import app       # noqa: E402

# Module-level logger. The Lambda runtime pre-configures the root logger.
logger = logging.getLogger(__name__)
logger.setLevel(os.getenv("LOG_LEVEL", "INFO"))

# `lifespan="off"` because Lambdas don't run lifespan events reliably
# across cold starts; we don't need any startup/shutdown hooks.
mangum_handler = Mangum(app, lifespan="off")


def _problem(status_code: int, detail: str) -> dict:
    """Build a v2-formatted response. Mangum also accepts a dict directly."""
    return {
        "statusCode": status_code,
        "headers": {"content-type": "application/json"},
        "body": json.dumps({"detail": detail}),
    }


def handler(event, context):
    """API Gateway HTTP API v2 entry point.

    Returns either:
    - A v2 response dict on success (API Gateway forwards the body to the client).
    - A clean 500 dict if Mangum raises, so the user sees a real error.
    """
    try:
        return mangum_handler(event, context)
    except Exception as exc:  # noqa: BLE001
        # Never let an exception escape a Lambda handler. AWS would
        # surface this as a generic 502 with no body, which is awful
        # to debug. We log it and return a structured 500 instead.
        logger.exception("mangum handler failure: %s", exc)
        return _problem(500, "Internal server error")
