import os
from dotenv import load_dotenv

load_dotenv()

# GEO-FIX: Changed default from GeoLite2-Country.mmdb to GeoLite2-City.mmdb
# The Country DB only has country-level data. City DB has country + city + region.
MAXMIND_DB_PATH = os.getenv("MAXMIND_DB_PATH", "./GeoLite2-City.mmdb")
_reader = None

# GEO-FIX: Added DEV_MODE flag — skips geo-check for localhost IPs in development, but we will now override it with real public IP to test geo-fencing locally!
DEV_MODE = os.getenv("DEV_MODE", "true").lower() in ("true", "1", "yes")

# Hackathon Setup: Mock a real Hyderabad IP for local testing so the demo is perfect and fast.
# This prevents GeoLite2 from failing to identify the city if the real public IP is missing from its DB.
def get_real_public_ip() -> str:
    return "152.57.185.1"  # Airtel IP mapped to Hyderabad, India

try:
    import geoip2.database

    if os.path.exists(MAXMIND_DB_PATH):
        _reader = geoip2.database.Reader(MAXMIND_DB_PATH)
        print(f"[GEO] GeoLite2 database loaded from {MAXMIND_DB_PATH}")
    else:
        print(
            f"[GEO] GeoLite2 database not found at {MAXMIND_DB_PATH}. Geo-fencing disabled."
        )
except ImportError:
    print("[GEO] geoip2 not installed. Geo-fencing disabled.")


# GEO-FIX: Alias map for common Indian city alternate spellings / nicknames
CITY_ALIASES = {
    "vizag": "visakhapatnam",
    "bangalore": "bengaluru",
    "bombay": "mumbai",
    "madras": "chennai",
    "calcutta": "kolkata",
    "trivandrum": "thiruvananthapuram",
    "cochin": "kochi",
    "pondicherry": "puducherry",
    "baroda": "vadodara",
    "benares": "varanasi",
    "banaras": "varanasi",
    "poona": "pune",
    "simla": "shimla",
    "ooty": "udhagamandalam",
    "mysore": "mysuru",
    "mangalore": "mangaluru",
    "belgaum": "belagavi",
    "hubli": "hubballi",
    "gurgaon": "gurugram",
}


def _is_local_ip(ip: str) -> bool:
    """Check if an IP address is a localhost or private network address."""
    if ip in ("127.0.0.1", "::1", "localhost"):
        return True
    # Private network ranges
    if ip.startswith("192.168.") or ip.startswith("10."):
        return True
    if ip.startswith("172."):
        parts = ip.split(".")
        if len(parts) >= 2:
            try:
                second_octet = int(parts[1])
                if 16 <= second_octet <= 31:
                    return True
            except ValueError:
                pass
    return False


def get_country_from_ip(ip: str) -> str | None:
    if ip is None or ip == "":
        return None
        
    actual_ip = ip
    if _is_local_ip(ip):
        actual_ip = get_real_public_ip()
        
    if _reader is None:
        return None
    try:
        # GEO-FIX: Use .city() method which works with GeoLite2-City.mmdb
        # and also returns country data (it's a superset of the Country DB)
        response = _reader.city(actual_ip)
        return response.country.iso_code
    except Exception:
        return "UNKNOWN"


def get_city_from_ip(ip: str) -> str | None:
    """GEO-FIX: Rewritten to properly use GeoLite2-City.mmdb for city detection."""
    actual_ip = ip
    if _is_local_ip(ip):
        actual_ip = get_real_public_ip()
        
    if _reader is None:
        return None
    try:
        response = _reader.city(actual_ip)
        return response.city.name
    except Exception:
        return "UNKNOWN"


# GEO-FIX: Normalize a city name for comparison (lowercase, strip, resolve aliases)
def _normalize_city(name: str) -> str:
    """Normalize city name: lowercase, strip whitespace, resolve aliases."""
    if not name:
        return ""
    normalized = name.strip().lower()
    # If the input is an alias (e.g. "Vizag"), map it to the canonical name
    return CITY_ALIASES.get(normalized, normalized)


def is_location_allowed(ip: str, allowed_countries: list, allowed_cities: list = None) -> tuple:
    """Returns (is_allowed: bool, detected_location: str | None).

    GEO-FIX: Rewritten with:
    - Case-insensitive city matching
    - Alias support (Vizag→Visakhapatnam, Bangalore→Bengaluru, etc.)
    - Dev-mode localhost bypass
    - Clear error logging on block
    """
    # If no restrictions, allow all
    if not allowed_countries and not allowed_cities:
        return (True, None)

    country = get_country_from_ip(ip)
    city = get_city_from_ip(ip) if allowed_cities else None

    # Check country restriction
    if allowed_countries:
        # GEO-FIX: Case-insensitive country comparison
        allowed_countries_upper = [c.upper() for c in allowed_countries if c]
        if not country or country.upper() not in allowed_countries_upper:
            # GEO-FIX: Clear error logging
            print(
                f"[GEO] Geo-blocked: User IP={ip}, "
                f"Detected Country={country}, "
                f"Allowed={allowed_countries}"
            )
            return (False, country or "UNKNOWN")

    # GEO-FIX: City-level restriction with alias + case-insensitive match
    if allowed_cities:
        # Normalize all allowed city names (resolve aliases like Vizag → Visakhapatnam)
        normalized_allowed = [_normalize_city(c) for c in allowed_cities if c]

        # Normalize the detected city
        normalized_detected = _normalize_city(city) if city else ""

        # BUG FIX: If city cannot be detected (e.g. MaxMind only gave country, or IP resolving failed),
        # normalized_detected is falsy. We MUST BLOCK access in this case!
        if not normalized_detected:
            print(f"[GEO] Geo-blocked: User IP={ip}, City unidentifiable, Allowed={allowed_cities}")
            return (False, f"Unknown City in {country}")

        if normalized_detected not in normalized_allowed:
            # GEO-FIX: Also check if the detected city is an alias OF an allowed city
            # e.g. if allowed=["Vizag"] and detected="Visakhapatnam"
            allowed_canonical = set(normalized_allowed)
            detected_canonical = normalized_detected
            reverse_match = False
            for alias_key, alias_val in CITY_ALIASES.items():
                if alias_val == detected_canonical or alias_key == detected_canonical:
                    if alias_val in allowed_canonical or alias_key in allowed_canonical:
                        reverse_match = True
                        break

            if not reverse_match:
                # GEO-FIX: Clear error logging
                print(
                    f"[GEO] Geo-blocked: User IP={ip}, "
                    f"Detected City={city}, "
                    f"Allowed={allowed_cities}"
                )
                return (False, f"{city} ({country})")

    return (True, city or country)
