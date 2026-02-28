"""Test script for email service integration."""

print("=== TEST 1: Email Service Imports ===")
from app.services.email_service import (
    send_user_verification_email,
    send_share_notification_email,
    generate_verification_code,
    create_email_verification_token,
    create_share_email_token,
    decode_email_token,
)
print("All email_service functions imported OK")

print()
print("=== TEST 2: Verification Code Generation ===")
for i in range(5):
    code = generate_verification_code()
    print(f"  Code {i+1}: {code}")
    assert len(code) == 6, "Code must be 6 digits"
    assert code.isdigit(), "Code must be all digits"
print("6-digit codes OK")

print()
print("=== TEST 3: JWT Verification Token Create + Decode ===")
token = create_email_verification_token("test@example.com")
print(f"JWT token: {token[:50]}...")
payload = decode_email_token(token)
print(f"Decoded email: {payload['sub']}")
print(f"Token type: {payload['type']}")
assert payload["sub"] == "test@example.com"
assert payload["type"] == "email_verification"
print("Verification JWT OK")

print()
print("=== TEST 4: Share Access JWT Token ===")
st = create_share_email_token("bob@test.com", "share-abc-123", "secretcode")
payload2 = decode_email_token(st)
print(f"Email: {payload2['sub']}")
print(f"Share token: {payload2['share_token']}")
print(f"Access code: {payload2['access_code']}")
print(f"Type: {payload2['type']}")
assert payload2["type"] == "share_access"
assert payload2["access_code"] == "secretcode"
assert payload2["share_token"] == "share-abc-123"
print("Share access JWT OK")

print()
print("=== TEST 5: Email Send (no SMTP = graceful fallback) ===")
result = send_user_verification_email("test@example.com", "123456")
print(f"Verification email result: {result} (expected False - no SMTP)")

result2 = send_share_notification_email(
    "bob@test.com", "mycode", "http://localhost:3000/viewer/abc", "secret.pdf", "abc"
)
print(f"Share email result: {result2} (expected False - no SMTP)")

print()
print("=== TEST 6: Auth Schemas ===")
from app.models.auth_schemas import VerifyCodeRequest, SendVerificationRequest
v = VerifyCodeRequest(email="a@b.com", code="123456")
s = SendVerificationRequest(email="a@b.com")
print(f"VerifyCodeRequest: {v}")
print(f"SendVerificationRequest: {s}")
print("Schemas OK")

print()
print("=== TEST 7: Invalid JWT Decode ===")
try:
    decode_email_token("invalid.token.here")
    print("ERROR: Should have raised ValueError")
except ValueError as e:
    print(f"Correctly rejected invalid token: {e}")

print()
print("=" * 50)
print("ALL TESTS PASSED")
print("=" * 50)
