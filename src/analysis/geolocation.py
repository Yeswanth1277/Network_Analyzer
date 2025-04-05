import geoip2.database
import os
import requests
from ipaddress import ip_address, IPv4Network, IPv4Address

DB_PATH = "data/geoip/GeoLite2-City.mmdb"

# Define private IP ranges and special addresses
PRIVATE_IP_RANGES = [
    IPv4Network("10.0.0.0/8"),
    IPv4Network("172.16.0.0/12"),
    IPv4Network("192.168.0.0/16"),
    IPv4Network("127.0.0.0/8")
]

# Multicast and special purpose addresses
SPECIAL_PURPOSE_RANGES = [
    IPv4Network("224.0.0.0/4"),  # Multicast
    IPv4Network("240.0.0.0/4"),  # Reserved
    IPv4Network("169.254.0.0/16")  # Link-local
]

def is_private_ip(ip):
    """Check if an IP address is private/local."""
    try:
        ip_obj = ip_address(ip)
        return any(ip_obj in network for network in PRIVATE_IP_RANGES)
    except ValueError:
        return True  # If we can't parse the IP, treat it as private

def is_special_purpose_ip(ip):
    """Check if an IP is a special purpose address (multicast, etc.)"""
    try:
        ip_obj = ip_address(ip)
        return any(ip_obj in network for network in SPECIAL_PURPOSE_RANGES)
    except ValueError:
        return False

def get_geolocation(ip):
    """Get geolocation of an IP using GeoLite2 with a backup API."""
    print(f"[DEBUG] Getting geolocation for IP: {ip}")
    
    # If IP is private, return "Local Network"
    if is_private_ip(ip):
        print(f"[INFO] IP {ip} is a private network address")
        return {
            "city": "Private Network",
            "country": "Local"
        }
    
    # If IP is a special purpose address
    if is_special_purpose_ip(ip):
        print(f"[INFO] IP {ip} is a special purpose address (multicast, etc.)")
        return {
            "city": "Special Purpose",
            "country": "Non-Geographic"
        }
    
    # Check if the GeoLite2 database exists
    if not os.path.exists(DB_PATH):
        print(f"[WARNING] GeoLite2 database not found at {DB_PATH}, using backup API")
        return get_geolocation_backup(ip)

    # Try to get geolocation from GeoLite2
    try:
        with geoip2.database.Reader(DB_PATH) as reader:
            try:
                response = reader.city(ip)
                return {
                    "city": response.city.name or "Unknown",
                    "country": response.country.name or "Unknown"
                }
            except geoip2.errors.AddressNotFoundError:
                print(f"[WARNING] GeoLite2 could not find {ip}, using backup API...")
                return get_geolocation_backup(ip)
    except Exception as e:
        print(f"[ERROR] GeoLite2 error: {e}, using backup API")
        return get_geolocation_backup(ip)

def get_geolocation_backup(ip):
    """Fallback geolocation lookup using multiple APIs if GeoLite2 fails."""
    # Try ip-api.com first
    try:
        print(f"[INFO] Trying ip-api.com for {ip}")
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
                print(f"[INFO] ip-api.com found location for {ip}: {data.get('city')}, {data.get('country')}")
                return {
                    "city": data.get("city", "Unknown"),
                    "country": data.get("country", "Unknown")
                }
            else:
                print(f"[WARNING] ip-api.com couldn't find {ip}: {data.get('message', 'No error message')}")
    except Exception as e:
        print(f"[ERROR] ip-api.com failed for {ip}: {e}")

    # Try ipinfo.io as a second backup
    try:
        print(f"[INFO] Trying ipinfo.io for {ip}")
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        if response.status_code == 200:
            data = response.json()
            print(f"[INFO] ipinfo.io found location for {ip}: {data.get('city')}, {data.get('country')}")
            return {
                "city": data.get("city", "Unknown"),
                "country": data.get("country", "Unknown")
            }
    except Exception as e:
        print(f"[ERROR] ipinfo.io failed for {ip}: {e}")

    # Try ipapi.co as a third backup
    try:
        print(f"[INFO] Trying ipapi.co for {ip}")
        response = requests.get(f"https://ipapi.co/{ip}/json/", timeout=5)
        if response.status_code == 200:
            data = response.json()
            print(f"[INFO] ipapi.co found location for {ip}: {data.get('city')}, {data.get('country_name')}")
            return {
                "city": data.get("city", "Unknown"),
                "country": data.get("country_name", "Unknown")
            }
    except Exception as e:
        print(f"[ERROR] ipapi.co failed for {ip}: {e}")

    # If all APIs fail, return Unknown
    print(f"[WARNING] All geolocation services failed for {ip}, returning Unknown")
    return {"city": "Unknown", "country": "Unknown"}