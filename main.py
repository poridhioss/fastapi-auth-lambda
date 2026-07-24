"""FastAPI app entry point for Lab 4.

This module is imported by both:
  - `lambda_handler.py` (production: behind Mangum in the Lambda)
  - local `uvicorn app.main:app` (development / unit testing)

Routes are mounted under `auth.py` so the surface area of `main.py`
stays minimal.

PRODUCTION NOTES:

* A global exception handler converts any uncaught exception into a
  structured JSON 500 instead of a stack trace. This means Lambda
  failures show up as proper API responses (and CloudWatch alarms can
  fire on 5xx rates).
* CORS is wide-open for the lab; tighten allow_origins before sharing a
  public URL.
"""

import logging
import os
import sys

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# Flat-zip layout for Lambda: ensure the zip root is on sys.path so
# `from auth import router` works without a parent package.
sys.path.insert(0, os.path.dirname(__file__))

from auth import router as auth_router  # noqa: E402

# Module-level logger. The Lambda runtime pre-configures the root logger.
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Lab 4: Serverless Auth API",
    version="0.1.0",
    description=(
        "Auth API on API Gateway (HTTP API) + Lambda authorizer + "
        "FastAPI/Mangum backend Lambda + DynamoDB (users + sessions)."
    ),
)

# Wide-open CORS is fine for a lab. Tighten before sharing a public URL.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router, tags=["auth"])


# ---------- Global exception handler ----------

@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    """Convert uncaught exceptions into a structured 500.

    Why: in Lambda, an uncaught exception at the top of FastAPI
    sometimes surfaces as an opaque Mangum error. Going through this
    handler means every error path is a JSON 500 the client can
    react to, and the stack trace still lands in CloudWatch.
    """
    logger.exception("unhandled exception on %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error"},
    )


@app.get("/")
def root():
    return {
        "status": "ok",
        "message": "Lab 4 serverless auth API. POST /signup, /login, /refresh; GET /me.",
    }


@app.get("/health")
def health():
    return {"status": "healthy"}


def configure_logging() -> None:
    """Optional: call once to set a structured log format.

    The Lambda runtime already sets up a log group; we just make sure
    log level is configurable from the env.
    """
    level = os.getenv("LOG_LEVEL", "INFO").upper()
    logging.getLogger().setLevel(level)