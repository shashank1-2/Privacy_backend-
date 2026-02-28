from jose import jwt, JWTError
import bcrypt
from datetime import datetime, timedelta
from fastapi import HTTPException
import os
from dotenv import load_dotenv

load_dotenv()

SECRET_KEY = os.getenv("JWT_SECRET_KEY", "fallback_dev_key")
ALGORITHM = "HS256"
EXPIRE_HOURS = int(os.getenv("JWT_EXPIRE_HOURS", "24"))


def hash_password(password: str) -> str:
    """Hash a password using bcrypt directly (compatible with bcrypt 4.1+)."""
    password_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode('utf-8')


def verify_password(plain: str, hashed: str) -> bool:
    """Verify a password against a bcrypt hash."""
    plain_bytes = plain.encode('utf-8')
    hashed_bytes = hashed.encode('utf-8')
    return bcrypt.checkpw(plain_bytes, hashed_bytes)


def create_access_token(user_id: str, role: str, expires_hours: int = None) -> str:
    if expires_hours is None:
        expires_hours = EXPIRE_HOURS
    payload = {
        "sub": user_id,
        "role": role,
        "exp": datetime.utcnow() + timedelta(hours=expires_hours),
        "type": "access",
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def create_view_token(share_token: str, file_id: str, expires_min: int = 15) -> str:
    payload = {
        "token": share_token,
        "file_id": file_id,
        "exp": datetime.utcnow() + timedelta(minutes=expires_min),
        "type": "view",
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
