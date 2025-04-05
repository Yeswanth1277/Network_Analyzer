import geoip2.database

DB_PATH = "data/geoip/GeoLite2-City.mmdb"
reader = geoip2.database.Reader(DB_PATH)

test_ips = ["8.8.8.8", "1.1.1.1", "104.26.3.102"]  # Cloudflare IP

for ip in test_ips:
    try:
        response = reader.city(ip)
        print(f"IP: {ip} → City: {response.city.name}, Country: {response.country.name}")
    except Exception as e:
        print(f"[ERROR] GeoLite2 lookup failed for {ip}: {e}")
