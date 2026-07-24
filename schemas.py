"""Pydantic models for Lab 4 request/response bodies."""

from pydantic import BaseModel, Field


class SignupRequest(BaseModel):
    """Body for POST /signup."""
    username: str = Field(min_length=3, max_length=50)
    email: str = Field(min_length=5, max_length=255)
    password: str = Field(min_length=8, max_length=72)
    # bcrypt has a 72-byte input cap; reject longer passwords up front.


class LoginRequest(BaseModel):
    """Body for POST /login."""
    email: str
    password: str


class RefreshRequest(BaseModel):
    """Body for POST /refresh."""
    refresh_token: str


class TokenPair(BaseModel):
    """Response for /signup, /login, and /refresh."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class MeResponse(BaseModel):
    """Response for GET /me."""
    user_id: str
    email: str
    username: str
    created_at: str | None = None