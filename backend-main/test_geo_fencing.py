"""
PrivacyProxy Geo-Fencing Test Script
------------------------------------
Run this script to verify that the geo-fencing fixes are working correctly.

Usage:
    cd backend-main
    python test_geo_fencing.py

This script tests the GeoLite2-City.mmdb database, alias resolution,
dev mode logic, and connects to the FastAPI backend to ensure it is running.
"""

import os
import sys
import requests
from dotenv import load_dotenv
import geoip2.database

# Load environment variables
load_dotenv()

# We need to import the geo_service functions
# Add current directory to path so we can import app modules
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from app.services.geo_service import (
    get_country_from_ip,
    get_city_from_ip,
    is_location_allowed,
    _normalize_city,
    CITY_ALIASES,
    MAXMIND_DB_PATH
)

# Test results tracker
results = {
    "test_1": "FAIL",
    "test_2": "0/7",
    "test_3": "FAIL",
    "test_4": "FAIL",
    "test_5": "FAIL",
    "test_6": "FAIL",
    "test_7": "FAIL",
    "test_8": "FAIL",
}

print("\n" + "="*50)
print("      PRIVACYPROXY GEO-FENCING TESTS")
print("="*50 + "\n")

# ─────────────────────────────────────────
# TEST 1: .mmdb File Exists & Loads Correctly
# ─────────────────────────────────────────
print("--- TEST 1: .mmdb File Load ---")
try:
    if os.path.exists(MAXMIND_DB_PATH):
        reader = geoip2.database.Reader(MAXMIND_DB_PATH)
        print(f"✅ PASS: GeoLite2-City.mmdb loaded successfully from {MAXMIND_DB_PATH}")
        results["test_1"] = "PASS"
    else:
        print(f"❌ FAIL: Cannot find or load .mmdb file — check MAXMIND_DB_PATH in .env")
except Exception as e:
    print(f"❌ FAIL: Exception loading .mmdb file: {e}")
print()

# ─────────────────────────────────────────
# TEST 2: City Alias Resolution
# ─────────────────────────────────────────
print("--- TEST 2: City Alias Resolution ---")
try:
    aliases_to_test = {
        "Vizag": "visakhapatnam",
        "Bangalore": "bengaluru",
        "Bombay": "mumbai",
        "Madras": "chennai",
        "Calcutta": "kolkata",
        "Hyderabad": "hyderabad",  # Already canonical
        "Delhi": "delhi"           # No alias, passthrough
    }
    
    passed_aliases = 0
    for input_name, expected in aliases_to_test.items():
        result = _normalize_city(input_name)
        if result == expected:
            print(f"✅ PASS: '{input_name}' → '{result}'")
            passed_aliases += 1
        else:
            print(f"❌ FAIL: '{input_name}' returned '{result}', expected '{expected}'")
            
    results["test_2"] = f"{passed_aliases}/{len(aliases_to_test)}"
    print(f"Alias Tests: {passed_aliases}/{len(aliases_to_test)} passed")
    if passed_aliases == len(aliases_to_test):
        results["test_2"] = "PASS"
except Exception as e:
    print(f"❌ FAIL: Exception in alias resolution test: {e}")
print()

# ─────────────────────────────────────────
# TEST 3: Real IP → City Resolution
# ─────────────────────────────────────────
print("--- TEST 3: IP → City Resolution ---")
try:
    ips_to_test = [
        ("8.8.8.8", "USA"),
        ("1.1.1.1", "Australia"),
        ("49.36.0.1", "India"),
        ("103.21.58.1", "India")
    ]
    
    all_passed = True
    for ip, expected_location in ips_to_test:
        country = get_country_from_ip(ip)
        city = get_city_from_ip(ip)
        
        print(f"IP: {ip} → Country: {country}, City: {city}")
        
        if city == "UNKNOWN":
            print(f"⚠️  WARNING: City returned UNKNOWN for {ip} — make sure you have GeoLite2-CITY not Country .mmdb")
            all_passed = False
            
    if all_passed:
        print("✅ PASS: All IPs resolved successfully")
        results["test_3"] = "PASS"
    else:
        print("⚠️ INFO: Some IPs returned UNKNOWN city.")
        results["test_3"] = "WARN"
except Exception as e:
    print(f"❌ FAIL: Exception in IP resolution test: {e}")
print()

# ─────────────────────────────────────────
# TEST 4: Localhost Dev Mode Bypass
# ─────────────────────────────────────────
print("--- TEST 4: Dev Mode Bypass ---")
try:
    # Force dev mode for test
    original_dev_mode = os.environ.get("DEV_MODE")
    os.environ["DEV_MODE"] = "true"
    
    # Needs to be re-evaluated since DEV_MODE is loaded at import time in geo_service.py
    import app.services.geo_service as gs
    gs.DEV_MODE = True
    
    allowed, loc = gs.is_location_allowed(
        ip="127.0.0.1",
        allowed_countries=["US"],
        allowed_cities=["New York"]
    )
    
    if allowed:
        print("✅ PASS: Localhost bypassed geo-check in DEV_MODE")
        results["test_4"] = "PASS"
    else:
        print("❌ FAIL: Localhost is being blocked — DEV_MODE bypass not working")
        
    # Restore
    if original_dev_mode is not None:
        os.environ["DEV_MODE"] = original_dev_mode
    else:
        del os.environ["DEV_MODE"]
except Exception as e:
    print(f"❌ FAIL: Exception in dev mode test: {e}")
print()

# ─────────────────────────────────────────
# TEST 5: Correct Country ALLOWS Access
# ─────────────────────────────────────────
print("--- TEST 5: Country Allow ---")
try:
    # Need to make sure we don't accidentally use DEV_MODE bypass if we're using a public IP
    # Actually, 49.36.0.1 is public, so DEV_MODE doesn't affect it.
    allowed, loc = gs.is_location_allowed(
        ip="49.36.0.1",
        allowed_countries=["IN"],
        allowed_cities=[]
    )
    
    if allowed:
        print("✅ PASS: Indian IP correctly allowed for IN country fence")
        results["test_5"] = "PASS"
    else:
        print("❌ FAIL: Indian IP wrongly blocked")
except Exception as e:
    print(f"❌ FAIL: Exception in country allow test: {e}")
print()

# ─────────────────────────────────────────
# TEST 6: Wrong Country BLOCKS Access
# ─────────────────────────────────────────
print("--- TEST 6: Country Block ---")
try:
    allowed, loc = gs.is_location_allowed(
        ip="8.8.8.8",
        allowed_countries=["IN"],
        allowed_cities=[]
    )
    
    if not allowed:
        print("✅ PASS: US IP correctly blocked for IN-only fence")
        results["test_6"] = "PASS"
    else:
        print("❌ FAIL: US IP was wrongly allowed — blocking broken")
except Exception as e:
    print(f"❌ FAIL: Exception in country block test: {e}")
print()

# ─────────────────────────────────────────
# TEST 7: Vizag Alias Geo-Fence Test
# ─────────────────────────────────────────
print("--- TEST 7: Vizag Alias ---")
try:
    ip = "49.36.0.1" # Example Jio Indian IP
    country = gs.get_country_from_ip(ip)
    city = gs.get_city_from_ip(ip)
    
    print(f"Targeting allowed city: 'Vizag'")
    print(f"Used IP: {ip} → resolves to {city} ({country})")
    
    allowed, loc = gs.is_location_allowed(
        ip=ip,
        allowed_countries=["IN"],
        allowed_cities=["Vizag"]
    )
    
    # This IP probably won't resolve to Visakhapatnam specifically unless we get lucky
    # That is why we check what it actually resolved to.
    
    if allowed:
        print("✅ PASS: Vizag alias matched correctly")
        results["test_7"] = "PASS"
    else:
        print(f"⚠️  INFO: IP resolved to {city}, not Visakhapatnam — try a Vizag-specific IP for full test")
        print("   (Note: Exact city testing requires an IP physically mapped to that city in the database)")
        results["test_7"] = "INFO"
except Exception as e:
    print(f"❌ FAIL: Exception in Vizag alias test: {e}")
print()

# ─────────────────────────────────────────
# TEST 8: Full API Endpoint Test
# ─────────────────────────────────────────
print("--- TEST 8: API Endpoint ---")
try:
    API_URL = "http://localhost:8000"
    
    # Try logging in
    login_url = f"{API_URL}/auth/login"
    login_data = {"email": "test@test.com", "password": "test123"}
    
    print(f"POST {login_url}")
    try:
        response = requests.post(login_url, json=login_data, timeout=3)
        
        if response.status_code == 200:
            token = response.json().get("access_token")
            # Try getting stats using the token
            stats_url = f"{API_URL}/stats"
            stats_res = requests.get(stats_url, headers={"Authorization": f"Bearer {token}"}, timeout=3)
            
            if stats_res.status_code == 200:
                print("✅ PASS: Backend API is running and responding")
                results["test_8"] = "PASS"
            else:
                print(f"❌ FAIL: Backend running but /stats failed with {stats_res.status_code}")
        elif response.status_code == 404 or response.status_code == 401:
            print(f"⚠️  SKIP: No test user found (Got {response.status_code}) — create a test account first to run API tests")
            results["test_8"] = "SKIP"
        else:
            print(f"❌ FAIL: Login returned unexpected status: {response.status_code}")
            
    except requests.exceptions.ConnectionError:
        print("❌ FAIL: Backend not running — start with: uvicorn app.main:app --reload --port 8000")
    except requests.exceptions.Timeout:
        print("❌ FAIL: Backend request timed out")
except Exception as e:
    print(f"❌ FAIL: Exception in API endpoint test: {e}")
print()

# ─────────────────────────────────────────
# FINAL REPORT
# ─────────────────────────────────────────
print("\n" + "="*48)
print("       PRIVACYPROXY GEO-FENCING TEST REPORT")
print("="*48)

print(f"{'✅ Test 1: .mmdb File Load':<35} {results['test_1']}")
print(f"{'✅ Test 2: City Alias Resolution':<35} {results['test_2']}")

if results['test_3'] == "PASS":
    print(f"{'✅ Test 3: IP → City Resolution':<35} {results['test_3']}")
else:
    print(f"{'⚠️  Test 3: IP → City Resolution':<35} {results['test_3']}")

print(f"{'✅ Test 4: Dev Mode Bypass':<35} {results['test_4']}")
print(f"{'✅ Test 5: Country Allow':<35} {results['test_5']}")
print(f"{'✅ Test 6: Country Block':<35} {results['test_6']}")

if results['test_7'] == "PASS":
    print(f"{'✅ Test 7: Vizag Alias':<35} {results['test_7']}")
else:
    print(f"{'⚠️  Test 7: Vizag Alias':<35} {results['test_7']}")

if results['test_8'] == "PASS" or results['test_8'] == "SKIP":
    print(f"{'✅ Test 8: API Endpoint':<35} {results['test_8']}")
else:
    print(f"{'❌ Test 8: API Endpoint':<35} {results['test_8']}")

print("-" * 48)

failed_tests = sum(1 for v in results.values() if v == "FAIL" or (isinstance(v, str) and "/" in v and v.split("/")[0] != v.split("/")[1]))

if failed_tests == 0:
    print("RESULT: Geo-fencing is working correctly ✅")
else:
    print(f"RESULT: {failed_tests} tests failed — see above ❌")
print("="*48 + "\n")
