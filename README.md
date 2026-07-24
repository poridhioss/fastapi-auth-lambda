# FastAPI Auth on AWS Lambda

A serverless auth API running FastAPI behind API Gateway HTTP API + Lambda
authorizer + DynamoDB. This is the Lambda variant of [fastApi-auth](https://github.com/poridhioss/fastApi-auth),
designed for AWS-only deployment with no EC2 or Docker.

## What you get

- `POST /signup` — create user, return access + refresh tokens
- `POST /login` — verify bcrypt, return access + refresh tokens
- `POST /refresh` — rotate refresh token
- `GET /me` — return the current user

A Lambda authorizer sits in front of `/me` and `/refresh` and verifies the
access token at the API Gateway edge.

## Architecture

```
Client -> API Gateway HTTP API -> (authorizer on /{proxy+}) -> Backend Lambda -> DynamoDB
                                  (verifies JWT)
```

## Files

| File | Purpose |
|---|---|
| `authorizer.py` | Lambda authorizer. Verifies the access JWT before the backend runs. |
| `lambda_handler.py` | Mangum adapter. Translates API Gateway HTTP API v2 events into ASGI scope for FastAPI. |
| `main.py` | FastAPI app entry point. |
| `auth.py` | Routes: `/signup`, `/login`, `/refresh`, `/me`. |
| `db.py` | boto3 DynamoDB helpers for `Users` and `Sessions` tables. |
| `jwt_utils.py` | JWT mint + verify. |
| `hashing.py` | bcrypt helpers. |
| `schemas.py` | Pydantic request/response models. |
| `requirements.txt` | Python dependencies. |
| `.env.example` | Environment variable template. |

## Deploy

1. Create two DynamoDB tables: `Users` (PK `user_id`, GSI `email-index` on
   `email`) and `Sessions` (PK `token`, TTL on `expires_at`).
2. Create an IAM role `Lab4LambdaRole` with `AWSLambdaBasicExecutionRole`
   and `AmazonDynamoDBFullAccess` (tighten in production).
3. Build the authorizer zip with `pyjwt` and the backend zip with the full
   `requirements.txt`. Both zips are flat (no `app/` folder) so absolute
   imports work on Lambda.
4. Create the two Lambdas (`AuthAuthorizer`, `AuthBackend`) on Python 3.12
   and upload the zips.
5. Set environment variables on both Lambdas (see `.env.example`).
6. Create an API Gateway HTTP API with these routes:
   - `GET /health`
   - `POST /signup`
   - `POST /login`
   - `ANY /{proxy+}` (with the authorizer attached)
7. Add the `JwtAuthorizer` Lambda authorizer on `/{proxy+}` with identity
   source `$request.header.Authorization`, payload format `2.0`, and
   simple responses enabled.

For full step-by-step instructions, see
[Lab 4 in bayajid-labs](https://github.com/poridhioss/bayajid-labs/tree/main/Python%20aws/Lab4).
