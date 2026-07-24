"""bcrypt helpers for Lab 4.

Identical to Lab 1-3 so password hashes would migrate cleanly if you ever
move back to EC2 + Postgres. The bcrypt module is CPU-bound at ~250 ms per
hash at cost=12; the Lambda is sized at 1024 MB specifically to give it
enough vCPU.
"""

import bcrypt

# 2^12 = 4096 rounds (~250 ms per hash on modern CPUs).
_BCRYPT_ROUNDS = 12


def hash_password(plain: str) -> str:
    """Turn a plain password into a bcrypt hash (with random salt)."""
    salt = bcrypt.gensalt(rounds=_BCRYPT_ROUNDS)
    return bcrypt.hashpw(plain.encode("utf-8"), salt).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    """Constant-time compare; returns True if the password matches the hash."""
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))