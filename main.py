import os
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt  # PyJWT
from fastapi import FastAPI, HTTPException, Depends, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# === Config ===
# add config
SECRET_KEY = "come on, this is really a password?"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15

app = FastAPI(title="JWT Demo Server")

# Demo user store (do NOT use plain-text in real apps)
USERS = {
    "alice": {"username": "alice", "password": "wonderland", "roles": ["user"]},
    "admin": {"username": "admin", "password": "admin", "roles": ["admin", "user"]},
}


def create_access_token(subject: str, roles: list[str], expires_minutes: int = ACCESS_TOKEN_EXPIRE_MINUTES) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": subject,          # subject (user identifier)
        "roles": roles,          # custom claim
        'game': 'fifa'
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

# === Routes ===
@app.get("/public")
def public():
    return {"message": create_access_token('itay hau', ['admin', 'user'])}

@app.post("/login")
def login(username: str, password: str):
    if not username or not password:
        raise HTTPException(status_code=400, detail="username and password are required")

    user = USERS.get(username)
    if not user or user["password"] != password:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_access_token(subject=user["username"], roles=user["roles"])
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60
    }


@app.get("/protected")
def protected(authorization: str = Header()):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    token = authorization.split(" ", 1)[1].strip()
    claims = None
    try:
        claims = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}")

    # payload = {
    #     "sub": subject,  # subject (user identifier)
    #     "roles": roles,  # custom claim
    #     'game': 'fifa'
    # }

    return {"message": f"Hello {claims['sub']}!", "roles": claims.get("roles", []), "claims": claims}


# pip install fastAPI uvicorn
# uvicorn main:app --port 9001 --reload
