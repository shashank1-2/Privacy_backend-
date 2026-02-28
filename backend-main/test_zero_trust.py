# test_zero_trust.py
import httpx

BASE = "http://localhost:8000"
client = httpx.Client(timeout=60.0)  # 60s timeout for PII scan

# 1. Login
r = client.post(f"{BASE}/auth/login", json={"email": "test@privacyvault.com", "password": "securepass123"})
token = r.json()["access_token"]
headers = {"Authorization": f"Bearer {token}"}
print("1. Login:", "✅" if r.status_code == 200 else "❌")

# 2. Get a file ID
r = client.get(f"{BASE}/vault/files", headers=headers)
files = r.json()
if not files:
    print("No files found. Upload one first.")
    exit()
file_id = files[0]["id"]
print(f"2. File ID: {file_id}")

# 3. Create share link
r = client.post(f"{BASE}/vault/share", headers=headers, json={
    "file_id": file_id,
    "recipient_email": "recipient@test.com",
    "access_code": "secret123",
    "security": {"expiry_hours": 24, "max_views": 5}
})
print(f"3. Share link created:", "✅" if r.status_code == 200 else f"❌ {r.status_code} {r.text[:200]}")
if r.status_code != 200:
    exit()
link = r.json()
share_token = link["token"]
print(f"   Token: {share_token[:8]}...")

# 4. Verify (zero-trust)
r = client.post(f"{BASE}/vault/verify/{share_token}", json={
    "email": "recipient@test.com",
    "access_code": "secret123"
})
print(f"4. Verification:", "✅" if r.status_code == 200 else f"❌ {r.status_code} {r.text[:200]}")
if r.status_code == 200:
    view_token = r.json()["view_token"]
    print(f"   View token obtained")

    # 5. Stream file
    r = client.get(f"{BASE}/vault/stream/{share_token}?view_token={view_token}")
    print(f"5. Stream file:", "✅" if r.status_code == 200 else f"❌ {r.status_code}")
    if r.status_code == 200:
        print(f"   Content type: {r.json().get('type', 'unknown')}")
        data_preview = r.json().get("data", "")[:80]
        print(f"   Data preview: {data_preview}")

# 6. Test wrong credentials
r = client.post(f"{BASE}/vault/verify/{share_token}", json={
    "email": "wrong@test.com",
    "access_code": "secret123"
})
print(f"6. Wrong email blocked:", "✅" if r.status_code == 403 else f"❌ {r.status_code}")

# 7. Screenshot report
r = client.post(f"{BASE}/vault/screenshot/{share_token}")
print(f"7. Screenshot report:", "✅" if r.status_code == 200 else f"❌ {r.status_code}")

# 8. Risk score
r = client.get(f"{BASE}/vault/risk/{share_token}", headers=headers)
print(f"8. Risk score:", "✅" if r.status_code == 200 else f"❌ {r.status_code}")
if r.status_code == 200:
    risk = r.json()
    print(f"   Score: {risk['score']}, Level: {risk['level']}")

print("\n🎉 Zero-trust flow complete!")
client.close()
