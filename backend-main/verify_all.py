# Full End-to-End Verification Script
import httpx
import time

BASE = "http://localhost:8000"
client = httpx.Client(timeout=60.0)
results = []

def check(label, condition, detail=""):
    status = "✅" if condition else "❌"
    results.append((label, status, detail))
    print(f"{status} {label} {detail}")

# ─── AUTH ───
print("\n=== AUTH ===")
r = client.post(f"{BASE}/auth/register", json={"email":"final@test.com","password":"finaltest1234","full_name":"Final Test"})
if r.status_code == 400 and "exists" in r.text.lower():
    # Already registered, login instead
    check("Register", True, "(already exists)")
else:
    check("Register", r.status_code == 200, f"status={r.status_code}")

r = client.post(f"{BASE}/auth/login", json={"email":"final@test.com","password":"finaltest1234"})
check("Login", r.status_code == 200, f"status={r.status_code}")
token = r.json().get("access_token", "")
headers = {"Authorization": f"Bearer {token}"}

r = client.get(f"{BASE}/auth/me", headers=headers)
check("Auth /me", r.status_code == 200, f"user={r.json().get('email','?')}")

# ─── EXISTING PII ROUTES ───
print("\n=== PII ROUTES ===")
r = client.post(f"{BASE}/sanitize", json={"text":"John Doe john@test.com","mode":"strict"})
check("Sanitize", r.status_code == 200, f"entities={r.json().get('items','?')}")

r = client.get(f"{BASE}/health")
check("Health", r.status_code == 200, f"status={r.json().get('status','?')}")

# ─── VAULT UPLOAD ───
print("\n=== VAULT ===")
r = client.post(f"{BASE}/vault/upload", headers=headers, files={"file": ("verify_test.txt", b"SSN 123-45-6789 Email: test@verify.com", "text/plain")})
check("Upload", r.status_code == 200, f"file_id={r.json().get('id','?')[:12]}...")
file_id = r.json().get("id", "")

r = client.get(f"{BASE}/vault/files", headers=headers)
check("List files", r.status_code == 200, f"count={len(r.json())}")

# ─── SHARING ───
print("\n=== SHARING ===")
r = client.post(f"{BASE}/vault/share", headers=headers, json={
    "file_id": file_id,
    "recipient_email": "r@test.com",
    "access_code": "code1234",
    "security": {"expiry_hours": 24, "max_views": 5}
})
check("Create share link", r.status_code == 200, f"token={r.json().get('token','?')[:8]}...")
share_token = r.json().get("token", "")

r = client.post(f"{BASE}/vault/verify/{share_token}", json={"email":"r@test.com","access_code":"code1234"})
check("Verify link", r.status_code == 200)
view_token = r.json().get("view_token", "")

r = client.get(f"{BASE}/vault/stream/{share_token}?view_token={view_token}")
check("Stream file", r.status_code == 200, f"type={r.json().get('type','?')}")

# ─── SECURITY ───
print("\n=== SECURITY ===")
r = client.post(f"{BASE}/vault/screenshot/{share_token}")
check("Screenshot report", r.status_code == 200)

r = client.get(f"{BASE}/vault/risk/{share_token}", headers=headers)
check("Risk score", r.status_code == 200, f"score={r.json().get('score','?')}, level={r.json().get('level','?')}")

r = client.get(f"{BASE}/vault/analytics", headers=headers)
check("Analytics", r.status_code == 200, f"files={r.json().get('total_files','?')}, links={r.json().get('total_links','?')}")

r = client.get(f"{BASE}/vault/security-events", headers=headers)
check("Security events", r.status_code == 200)

r = client.get(f"{BASE}/vault/links", headers=headers)
check("List links", r.status_code == 200, f"count={len(r.json().get('links',[]))}")

# ─── WRONG CREDS ───
print("\n=== NEGATIVE TESTS ===")
r = client.post(f"{BASE}/vault/verify/{share_token}", json={"email":"wrong@test.com","access_code":"code1234"})
check("Wrong email blocked", r.status_code == 403)

r = client.post(f"{BASE}/vault/verify/{share_token}", json={"email":"r@test.com","access_code":"wrongcode"})
check("Wrong code blocked", r.status_code == 403)

# ─── OPENAPI ───
print("\n=== OPENAPI ===")
r = client.get(f"{BASE}/openapi.json")
routes = [p for p in r.json().get("paths", {}).keys()]
vault_routes = [p for p in routes if "/vault" in p]
check("OpenAPI spec", r.status_code == 200, f"total_routes={len(routes)}, vault_routes={len(vault_routes)}")

# ─── SUMMARY ───
print("\n" + "="*50)
passed = sum(1 for _, s, _ in results if s == "✅")
failed = sum(1 for _, s, _ in results if s == "❌")
print(f"RESULTS: {passed} passed, {failed} failed, {len(results)} total")
if failed == 0:
    print("🎉 ALL BACKEND TESTS PASSED!")
else:
    print("⚠️ Some tests failed:")
    for label, status, detail in results:
        if status == "❌":
            print(f"  {label}: {detail}")

client.close()
