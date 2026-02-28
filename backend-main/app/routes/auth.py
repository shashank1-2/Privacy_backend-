from fastapi import APIRouter, HTTPException, Depends, Response, Request, Query
from datetime import datetime, timedelta
import uuid
from bson import ObjectId
from app.database import users_col, audit_col
from app.models.auth_schemas import (
    UserCreate,
    UserLogin,
    TokenResponse,
    UserResponse,
    ForgotPasswordRequest,
    ResetPasswordRequest,
    VerifyCodeRequest,
    SendVerificationRequest,
)
from app.services.auth_service import hash_password, verify_password, create_access_token
from app.services.email_service import (
    send_user_verification_email,
    generate_verification_code,
    decode_email_token,
)
from app.dependencies import get_current_user

router = APIRouter(prefix="/auth", tags=["Authentication"])

# Simplified in-memory store for reset tokens (in production use Redis or DB)
RESET_TOKENS = {}


@router.post("/register", response_model=TokenResponse)
async def register(body: UserCreate, response: Response, request: Request):
    existing = await users_col.find_one({"email": body.email.lower().strip()})
    if existing:
        raise HTTPException(status_code=409, detail="Email already registered")

    user_doc = {
        "email": body.email.lower().strip(),
        "password_hash": hash_password(body.password),
        "full_name": body.full_name.strip(),
        "role": "user",
        "is_active": True,
        "email_verified": False,
        "created_at": datetime.utcnow(),
        "last_login": None,
        "verification_code": generate_verification_code(),
        "verification_code_expires": datetime.utcnow() + timedelta(hours=24),
        "settings": {
            "default_redaction_mode": "strict",
            "default_expiry_hours": 24,
            "notify_on_access": True,
        },
    }

    result = await users_col.insert_one(user_doc)
    user_id = str(result.inserted_id)
    token = create_access_token(user_id, "user")

    # Set Secure httpOnly Cookie
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        secure=True,  # Set to True in production
        samesite="lax",
        max_age=24 * 3600,
    )

    await audit_col.insert_one({
        "event_type": "user_register",
        "timestamp": datetime.utcnow(),
        "user_id": user_id,
        "metadata": {"email": user_doc["email"]},
        "request": {"ip": request.client.host if request.client else "unknown"}
    })

    # Send verification email (non-blocking — don't fail registration if email fails)
    try:
        send_user_verification_email(user_doc["email"], user_doc["verification_code"])
        print(f"[EMAIL] Verification email sent to {user_doc['email']}")
    except Exception as e:
        print(f"[EMAIL] ⚠️ Failed to send verification email: {e}")

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        user=UserResponse(
            id=user_id,
            email=user_doc["email"],
            full_name=user_doc["full_name"],
            role="user",
            is_active=True,
            email_verified=False,
            created_at=str(user_doc["created_at"]),
        ),
    )


@router.post("/login", response_model=TokenResponse)
async def login(body: UserLogin, response: Response, request: Request):
    user = await users_col.find_one({"email": body.email.lower().strip()})
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user.get("password_hash"):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not verify_password(body.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user.get("is_active", False):
        raise HTTPException(status_code=403, detail="Account disabled")

    await users_col.update_one(
        {"_id": user["_id"]}, {"$set": {"last_login": datetime.utcnow()}}
    )

    user_id = str(user["_id"])
    token = create_access_token(user_id, user.get("role", "user"))

    # Set Secure httpOnly Cookie
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=24 * 3600,
    )

    await audit_col.insert_one({
        "event_type": "user_login",
        "timestamp": datetime.utcnow(),
        "user_id": user_id,
        "metadata": {"email": user["email"]},
        "request": {"ip": request.client.host if request.client else "unknown"}
    })

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        user=UserResponse(
            id=user_id,
            email=user["email"],
            full_name=user["full_name"],
            role=user.get("role", "user"),
            is_active=user.get("is_active", True),
            email_verified=user.get("email_verified", False),
            created_at=str(user.get("created_at", "")),
        ),
    )


@router.post("/logout")
async def logout(response: Response):
    response.delete_cookie("access_token")
    return {"message": "Logged out successfully"}


@router.get("/me", response_model=UserResponse)
async def get_me(current_user: dict = Depends(get_current_user)):
    return UserResponse(
        id=str(current_user["_id"]),
        email=current_user["email"],
        full_name=current_user["full_name"],
        role=current_user.get("role", "user"),
        is_active=current_user.get("is_active", True),
        email_verified=current_user.get("email_verified", False),
        created_at=str(current_user.get("created_at", "")),
    )


@router.post("/forgot-password")
async def forgot_password(body: ForgotPasswordRequest):
    user = await users_col.find_one({"email": body.email.lower().strip()})
    if not user:
        # Return 200 even if email not found for security
        return {"message": "If this email is registered, a reset link will be sent."}

    # Generate token
    token = str(uuid.uuid4())
    RESET_TOKENS[token] = {
        "user_id": str(user["_id"]),
        "expires": datetime.utcnow() + timedelta(hours=1),
    }

    print(f"DEBUG: Password reset link: http://localhost:3000/reset-password?token={token}")
    # In production, send email here
    return {"message": "If this email is registered, a reset link will be sent."}


@router.post("/reset-password")
async def reset_password(body: ResetPasswordRequest, request: Request):
    token_data = RESET_TOKENS.get(body.token)
    if not token_data or token_data["expires"] < datetime.utcnow():
        if body.token in RESET_TOKENS:
            del RESET_TOKENS[body.token]
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    user_id = token_data["user_id"]
    await users_col.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {"password_hash": hash_password(body.new_password)}},
    )

    await audit_col.insert_one({
        "event_type": "password_reset",
        "timestamp": datetime.utcnow(),
        "user_id": user_id,
        "metadata": {"token": body.token},
        "request": {"ip": request.client.host if request.client else "unknown"}
    })

    del RESET_TOKENS[body.token]
    return {"message": "Password updated successfully"}


# ──────────────────────────────────────────────
# POST /auth/verify-code — Validate 6-digit email code
# ──────────────────────────────────────────────
@router.post("/verify-code")
async def verify_code(body: VerifyCodeRequest):
    user = await users_col.find_one({"email": body.email.lower().strip()})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.get("email_verified"):
        return {"message": "Email already verified", "verified": True}

    stored_code = user.get("verification_code", "")
    code_expires = user.get("verification_code_expires", datetime.utcnow())

    if code_expires < datetime.utcnow():
        raise HTTPException(status_code=400, detail="Verification code has expired. Please request a new one.")

    if stored_code != body.code:
        raise HTTPException(status_code=400, detail="Invalid verification code")

    # Mark email as verified
    await users_col.update_one(
        {"_id": user["_id"]},
        {
            "$set": {"email_verified": True},
            "$unset": {"verification_code": "", "verification_code_expires": ""},
        },
    )

    await audit_col.insert_one({
        "event_type": "email_verified",
        "timestamp": datetime.utcnow(),
        "user_id": str(user["_id"]),
        "metadata": {"email": user["email"], "method": "code"},
    })

    print(f"[AUTH] ✅ Email verified via code for {user['email']}")
    return {"message": "Email verified successfully", "verified": True}


# ──────────────────────────────────────────────
# POST /auth/send-verification — Resend verification email
# ──────────────────────────────────────────────
@router.post("/send-verification")
async def send_verification(body: SendVerificationRequest):
    user = await users_col.find_one({"email": body.email.lower().strip()})
    if not user:
        # Don't reveal if email exists — return success either way
        return {"message": "If this email is registered, a verification email will be sent."}

    if user.get("email_verified"):
        return {"message": "Email is already verified."}

    # Generate fresh code
    new_code = generate_verification_code()
    await users_col.update_one(
        {"_id": user["_id"]},
        {
            "$set": {
                "verification_code": new_code,
                "verification_code_expires": datetime.utcnow() + timedelta(hours=24),
            }
        },
    )

    try:
        send_user_verification_email(user["email"], new_code)
        print(f"[EMAIL] Resent verification email to {user['email']}")
    except Exception as e:
        print(f"[EMAIL] ⚠️ Failed to resend verification email: {e}")

    return {"message": "If this email is registered, a verification email will be sent."}


# ──────────────────────────────────────────────
# GET /auth/verify?token=... — Magic link verification
# ──────────────────────────────────────────────
@router.get("/verify")
async def verify_magic_link(token: str = Query(...)):
    try:
        payload = decode_email_token(token)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if payload.get("type") != "email_verification":
        raise HTTPException(status_code=400, detail="Invalid token type")

    email = payload.get("sub", "").lower().strip()
    user = await users_col.find_one({"email": email})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.get("email_verified"):
        return {"message": "Email already verified", "verified": True, "email": email}

    await users_col.update_one(
        {"_id": user["_id"]},
        {
            "$set": {"email_verified": True},
            "$unset": {"verification_code": "", "verification_code_expires": ""},
        },
    )

    await audit_col.insert_one({
        "event_type": "email_verified",
        "timestamp": datetime.utcnow(),
        "user_id": str(user["_id"]),
        "metadata": {"email": email, "method": "magic_link"},
    })

    print(f"[AUTH] ✅ Email verified via magic link for {email}")
    return {"message": "Email verified successfully", "verified": True, "email": email}
