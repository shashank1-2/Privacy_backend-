import hashlib
import os
from dotenv import load_dotenv
from fastapi import Request

load_dotenv()
SALT = os.getenv("DEVICE_HASH_SALT", "default_salt")


def compute_device_hash(user_agent: str, ip: str) -> str:
    raw = f"{user_agent}|{ip}|{SALT}"
    return hashlib.sha256(raw.encode()).hexdigest()


def get_request_info(request: Request) -> dict:
    ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")
    device_hash = compute_device_hash(user_agent, ip)
    return {"ip": ip, "user_agent": user_agent, "device_hash": device_hash}
