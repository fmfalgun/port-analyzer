import secrets
import re
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, EmailStr
from port_analyzer.cache import get_db, create_api_key, email_exists, get_api_key

router = APIRouter(prefix="/api/v1", tags=["auth"])

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class RegisterRequest(BaseModel):
    email: str


class RegisterResponse(BaseModel):
    api_key: str
    email: str
    rate_limit: int
    message: str


@router.post("/register", response_model=RegisterResponse)
def register(body: RegisterRequest, request: Request):
    email = body.email.strip().lower()

    if not EMAIL_RE.match(email):
        raise HTTPException(status_code=400, detail="Invalid email address")

    db = get_db()
    try:
        if email_exists(db, email):
            raise HTTPException(
                status_code=409,
                detail="This email already has an API key. Check your inbox or contact support."
            )

        key = "pa-" + secrets.token_urlsafe(32)
        create_api_key(db, email, key, rate_limit=1000)

        return RegisterResponse(
            api_key=key,
            email=email,
            rate_limit=1000,
            message="Key generated. Include it as X-API-Key header in requests."
        )
    finally:
        db.close()


@router.get("/key/info")
def key_info(request: Request):
    key = request.headers.get("X-API-Key")
    if not key:
        raise HTTPException(status_code=401, detail="X-API-Key header required")

    db = get_db()
    try:
        row = get_api_key(db, key)
        if not row:
            raise HTTPException(status_code=401, detail="Invalid API key")
        return {
            "email":           row["email"],
            "created_at":      row["created_at"],
            "last_used":       row["last_used"],
            "requests_today":  row["requests_today"],
            "rate_limit":      row["rate_limit"],
        }
    finally:
        db.close()
