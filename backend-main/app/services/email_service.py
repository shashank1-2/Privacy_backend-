"""
EmailService — Production-Ready Email Verification & Notification System

Features:
- Hybrid verification: 6-digit codes + JWT Magic Links
- Branded dark-themed HTML templates (PrivacyProxy style)
- SMTP integration (optimized for Gmail App Passwords)
- JWT tokens signed with HS256, 24-hour expiry
- MIMEMultipart with Plain Text + HTML for high deliverability
"""

import os
import smtplib
import secrets
import hashlib
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from jose import jwt
from dotenv import load_dotenv

load_dotenv()

# ──────────────────────────────────────────────
# Configuration from environment
# ──────────────────────────────────────────────
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
EMAIL_USER = os.getenv("EMAIL_USER", "")
EMAIL_PASS = os.getenv("EMAIL_PASS", "")
APP_URL = os.getenv("APP_URL", "http://localhost:3000")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "fallback_dev_key")
JWT_ALGORITHM = "HS256"
VERIFICATION_EXPIRY_HOURS = 24


# ──────────────────────────────────────────────
# JWT Helper functions for email tokens
# ──────────────────────────────────────────────
def create_email_verification_token(email: str) -> str:
    """Create a JWT magic-link token for user email verification."""
    payload = {
        "sub": email,
        "type": "email_verification",
        "exp": datetime.utcnow() + timedelta(hours=VERIFICATION_EXPIRY_HOURS),
        "iat": datetime.utcnow(),
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def create_share_email_token(email: str, share_token: str, access_code: str) -> str:
    """Create a JWT token embedding share link + access code for one-click access."""
    payload = {
        "sub": email,
        "share_token": share_token,
        "access_code": access_code,
        "type": "share_access",
        "exp": datetime.utcnow() + timedelta(hours=VERIFICATION_EXPIRY_HOURS),
        "iat": datetime.utcnow(),
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def decode_email_token(token: str) -> dict:
    """Decode and validate an email JWT token. Returns payload or raises."""
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except Exception as e:
        raise ValueError(f"Invalid or expired token: {e}")


# ──────────────────────────────────────────────
# 6-Digit Verification Code Generator
# ──────────────────────────────────────────────
def generate_verification_code() -> str:
    """Generate a cryptographically secure 6-digit code."""
    return f"{secrets.randbelow(900000) + 100000}"


# ──────────────────────────────────────────────
# HTML Template Builder — Premium Dark Theme
# ──────────────────────────────────────────────
def _build_email_html(
    heading: str,
    body_content: str,
    footer_note: str = "",
) -> str:
    """
    Build a branded, dark-themed HTML email wrapper.
    PrivacyProxy style with gradient accents.
    """
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{heading}</title>
</head>
<body style="margin:0; padding:0; background-color:#0a0a0f; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#0a0a0f; padding:40px 20px;">
<tr><td align="center">
<table role="presentation" width="600" cellpadding="0" cellspacing="0" style="background-color:#111118; border-radius:16px; border:1px solid rgba(255,255,255,0.06); overflow:hidden; box-shadow:0 25px 50px rgba(0,0,0,0.5);">

<!-- Header -->
<tr><td style="background: linear-gradient(135deg, #2563eb 0%, #7c3aed 100%); padding:32px 40px; text-align:center;">
    <h1 style="margin:0; color:#ffffff; font-size:24px; font-weight:700; letter-spacing:-0.5px;">
        🛡️ PrivacyProxy
    </h1>
    <p style="margin:8px 0 0; color:rgba(255,255,255,0.8); font-size:13px; letter-spacing:0.5px;">
        Zero-Trust Secure Platform
    </p>
</td></tr>

<!-- Body -->
<tr><td style="padding:40px;">
    <h2 style="margin:0 0 20px; color:#ffffff; font-size:20px; font-weight:600;">
        {heading}
    </h2>
    {body_content}
</td></tr>

<!-- Footer -->
<tr><td style="padding:24px 40px; background-color:#0d0d14; border-top:1px solid rgba(255,255,255,0.05);">
    <p style="margin:0; color:rgba(255,255,255,0.3); font-size:11px; text-align:center; line-height:1.6;">
        {footer_note if footer_note else "This is an automated message from PrivacyProxy. Do not reply to this email."}
        <br>
        &copy; {datetime.utcnow().year} PrivacyProxy — All rights reserved.
    </p>
</td></tr>

</table>
</td></tr>
</table>
</body>
</html>"""


# ──────────────────────────────────────────────
# SMTP Send Helper
# ──────────────────────────────────────────────
def _send_email(to_email: str, subject: str, plain_text: str, html_content: str) -> bool:
    """
    Send a MIMEMultipart email with both plain text and HTML.
    Returns True on success, False on failure (logs warning).
    """
    if not EMAIL_USER or not EMAIL_PASS:
        print(f"[EMAIL] ⚠️ SMTP not configured (EMAIL_USER/EMAIL_PASS missing). "
              f"Would have sent '{subject}' to {to_email}")
        print(f"[EMAIL] Plain text preview:\n{plain_text[:300]}")
        return False

    msg = MIMEMultipart("alternative")
    msg["From"] = f"PrivacyProxy <{EMAIL_USER}>"
    msg["To"] = to_email
    msg["Subject"] = subject

    # Attach plain text first (fallback), then HTML (preferred)
    msg.attach(MIMEText(plain_text, "plain"))
    msg.attach(MIMEText(html_content, "html"))

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(EMAIL_USER, EMAIL_PASS)
            server.send_message(msg)
        print(f"[EMAIL] ✅ Sent '{subject}' to {to_email}")
        return True
    except Exception as e:
        print(f"[EMAIL] ❌ Failed to send '{subject}' to {to_email}: {e}")
        return False


# ══════════════════════════════════════════════
# PUBLIC API: User Verification Email
# ══════════════════════════════════════════════
def send_user_verification_email(email: str, code: str) -> bool:
    """
    Send a registration verification email with:
    - 6-digit access code for manual entry
    - JWT magic link for one-click verification
    """
    magic_token = create_email_verification_token(email)
    magic_link = f"{APP_URL}/auth/verify?token={magic_token}"

    subject = "🔐 Verify Your PrivacyProxy Account"

    plain_text = (
        f"Welcome to PrivacyProxy!\n\n"
        f"Your verification code is: {code}\n\n"
        f"Or click this link to verify instantly:\n{magic_link}\n\n"
        f"This code expires in {VERIFICATION_EXPIRY_HOURS} hours.\n\n"
        f"If you did not create this account, please ignore this email."
    )

    body_html = f"""
    <p style="color:rgba(255,255,255,0.7); font-size:15px; line-height:1.7; margin:0 0 24px;">
        Welcome! Please verify your email address to activate your PrivacyProxy account.
    </p>

    <!-- Verification Code Box -->
    <div style="background: linear-gradient(135deg, rgba(37,99,235,0.15), rgba(124,58,237,0.15)); border:1px solid rgba(37,99,235,0.3); border-radius:12px; padding:28px; text-align:center; margin:0 0 28px;">
        <p style="margin:0 0 8px; color:rgba(255,255,255,0.5); font-size:11px; text-transform:uppercase; letter-spacing:2px; font-weight:600;">
            Your Verification Code
        </p>
        <p style="margin:0; color:#ffffff; font-size:36px; font-weight:800; letter-spacing:8px; font-family:monospace;">
            {code}
        </p>
        <p style="margin:12px 0 0; color:rgba(255,255,255,0.4); font-size:12px;">
            Expires in {VERIFICATION_EXPIRY_HOURS} hours
        </p>
    </div>

    <!-- OR Divider -->
    <div style="text-align:center; margin:24px 0;">
        <span style="color:rgba(255,255,255,0.3); font-size:12px; text-transform:uppercase; letter-spacing:2px;">
            — or verify instantly —
        </span>
    </div>

    <!-- Magic Link Button -->
    <div style="text-align:center; margin:0 0 28px;">
        <a href="{magic_link}" target="_blank"
           style="display:inline-block; background:linear-gradient(135deg, #2563eb, #7c3aed); color:#ffffff; text-decoration:none; padding:14px 40px; border-radius:8px; font-size:14px; font-weight:600; letter-spacing:0.5px;">
            ✅ Verify My Email
        </a>
    </div>

    <p style="color:rgba(255,255,255,0.4); font-size:12px; line-height:1.6;">
        If you did not create an account on PrivacyProxy, you can safely ignore this email.
    </p>
    """

    html_content = _build_email_html(
        heading="Verify Your Email",
        body_content=body_html,
        footer_note="You received this because someone registered with this email on PrivacyProxy.",
    )

    return _send_email(email, subject, plain_text, html_content)


# ══════════════════════════════════════════════
# PUBLIC API: Share Link Notification Email
# ══════════════════════════════════════════════
def send_share_notification_email(
    recipient: str,
    access_code: str,
    share_url: str,
    filename: str,
    share_token: str = "",
) -> bool:
    """
    Send a secure file sharing notification email with:
    - Share link URL
    - Access code for verification
    - JWT one-click access token (auto-fills email + code)
    """
    # Build the one-click JWT magic link
    vt_token = ""
    one_click_url = share_url
    if share_token:
        vt_token = create_share_email_token(recipient, share_token, access_code)
        one_click_url = f"{share_url}?vt={vt_token}"

    subject = f"🔒 Secure File Shared With You: {filename}"

    plain_text = (
        f"A secure file has been shared with you on PrivacyProxy.\n\n"
        f"File: {filename}\n"
        f"Share Link: {share_url}\n"
        f"Access Code: {access_code}\n\n"
        f"Or use this one-click link to access instantly:\n{one_click_url}\n\n"
        f"This link may have view limits, geo-restrictions, or time-based expiry.\n"
        f"Do not share this email with anyone."
    )

    body_html = f"""
    <p style="color:rgba(255,255,255,0.7); font-size:15px; line-height:1.7; margin:0 0 24px;">
        A secure document has been shared with you through PrivacyProxy's zero-trust platform.
    </p>

    <!-- File Info Card -->
    <div style="background:rgba(255,255,255,0.03); border:1px solid rgba(255,255,255,0.08); border-radius:12px; padding:20px; margin:0 0 24px;">
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
        <tr>
            <td style="width:48px; vertical-align:top;">
                <div style="width:44px; height:44px; background:linear-gradient(135deg, #2563eb, #7c3aed); border-radius:10px; text-align:center; line-height:44px; font-size:20px;">
                    📄
                </div>
            </td>
            <td style="padding-left:16px; vertical-align:top;">
                <p style="margin:0 0 4px; color:#ffffff; font-size:15px; font-weight:600;">
                    {filename}
                </p>
                <p style="margin:0; color:rgba(255,255,255,0.4); font-size:12px;">
                    Encrypted &amp; Protected · Zero-Trust Access
                </p>
            </td>
        </tr>
        </table>
    </div>

    <!-- Access Code Box -->
    <div style="background: linear-gradient(135deg, rgba(37,99,235,0.15), rgba(124,58,237,0.15)); border:1px solid rgba(37,99,235,0.3); border-radius:12px; padding:24px; text-align:center; margin:0 0 24px;">
        <p style="margin:0 0 6px; color:rgba(255,255,255,0.5); font-size:11px; text-transform:uppercase; letter-spacing:2px; font-weight:600;">
            Your Access Code
        </p>
        <p style="margin:0; color:#ffffff; font-size:32px; font-weight:800; letter-spacing:6px; font-family:monospace;">
            {access_code}
        </p>
    </div>

    <!-- One-Click Button -->
    <div style="text-align:center; margin:0 0 20px;">
        <a href="{one_click_url}" target="_blank"
           style="display:inline-block; background:linear-gradient(135deg, #2563eb, #7c3aed); color:#ffffff; text-decoration:none; padding:14px 40px; border-radius:8px; font-size:14px; font-weight:600; letter-spacing:0.5px;">
            🔓 Open Secure Document
        </a>
    </div>

    <p style="color:rgba(255,255,255,0.35); font-size:12px; text-align:center; margin:0 0 20px;">
        One-click access auto-fills your credentials for seamless entry.
    </p>

    <!-- Security Notice -->
    <div style="background:rgba(245,158,11,0.08); border:1px solid rgba(245,158,11,0.2); border-radius:8px; padding:16px; margin:0 0 8px;">
        <p style="margin:0; color:rgba(245,158,11,0.9); font-size:12px; line-height:1.6;">
            ⚠️ <strong>Security Notice:</strong> This link may have view limits, geo-restrictions, device locking, or expiry constraints.
            Do not forward this email to anyone. The access code is intended only for you.
        </p>
    </div>
    """

    html_content = _build_email_html(
        heading="Secure File Shared With You",
        body_content=body_html,
        footer_note="You received this because someone shared a document with you via PrivacyProxy.",
    )

    return _send_email(recipient, subject, plain_text, html_content)
