# src/analysis/reputation.py
import requests
import time
import os
import logging
from src.analysis.geolocation import is_private_ip # Reuse check

log_reputation = logging.getLogger('sniffer.reputation') # Sub-logger

# --- IP Reputation Check using AbuseIPDB (Example) ---
# Requires an API Key set in environment variable ABUSEIPDB_API_KEY
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY")
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

# Note: Simple in-memory cache. See limitations mentioned earlier.
def check_ip_reputation(ip_address, cache, cache_ttl=3600):
    """
    Checks IP reputation using AbuseIPDB API with caching.

    Args:
        ip_address (str): The public IP address to check.
        cache (dict): Shared dictionary for caching results.
        cache_ttl (int): Time-to-live for cache entries in seconds.

    Returns:
        dict or None: Threat details if the IP is found malicious, otherwise None.
    """
    if not ABUSEIPDB_API_KEY:
        log_reputation.debug("AbuseIPDB API key not configured. Skipping reputation check.")
        return None

    if is_private_ip(ip_address):
        # log_reputation.debug(f"Skipping reputation check for private IP: {ip_address}")
        return None

    current_time = time.time()

    # Check cache first
    if ip_address in cache:
        entry = cache[ip_address]
        if current_time - entry['timestamp'] < cache_ttl:
            log_reputation.debug(f"Using cached reputation for {ip_address}: {entry['status']}")
            if entry['status'] == 'malicious':
                return entry['threat_details'] # Return cached threat info
            else:
                return None # Return None if cached as clean/unknown

    # --- Perform API Lookup ---
    log_reputation.info(f"Querying AbuseIPDB for IP: {ip_address}")
    headers = {
        'Accept': 'application/json',
        'Key': ABUSEIPDB_API_KEY
    }
    querystring = {
        'ipAddress': ip_address,
        'maxAgeInDays': '90', # Look back 90 days
        #'verbose': '' # Uncomment for more details
    }

    threat = None
    status = 'unknown' # Default status

    try:
        response = requests.get(url=ABUSEIPDB_URL, headers=headers, params=querystring, timeout=5)
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)

        data = response.json().get('data', {})
        confidence_score = data.get('abuseConfidenceScore', 0)

        # --- Determine Threat Based on Score ---
        # Adjust this threshold as needed based on your tolerance
        if confidence_score >= 75: # Example threshold
            status = 'malicious'
            threat = {
                "signature_id": "REPU-IP-MALICIOUS",
                "description": f"Connection involving known malicious IP: {ip_address} (Score: {confidence_score}%)",
                "severity": "High",
                "type": "Reputation",
                "details": { # Add extra info if needed
                    "domain": data.get("domain"),
                    "isp": data.get("isp"),
                    "usageType": data.get("usageType"),
                    "countryCode": data.get("countryCode")
                }
            }
            log_reputation.warning(f"Malicious IP detected: {ip_address} (Score: {confidence_score})")
        elif confidence_score > 0:
             status = 'suspicious' # Could log this differently if needed
             log_reputation.info(f"IP {ip_address} has non-zero abuse score: {confidence_score}")
        else:
            status = 'clean'
            log_reputation.info(f"IP {ip_address} appears clean according to AbuseIPDB.")

    except requests.exceptions.Timeout:
        log_reputation.error(f"Timeout connecting to AbuseIPDB for IP: {ip_address}")
        status = 'error_timeout'
    except requests.exceptions.RequestException as e:
        log_reputation.error(f"Error querying AbuseIPDB for IP {ip_address}: {e}")
        status = 'error_request'
    except Exception as e:
        log_reputation.error(f"Unexpected error during IP reputation check for {ip_address}: {e}")
        status = 'error_unexpected'


    # --- Update Cache ---
    # Cache even errors/unknowns to prevent hammering the API
    cache_entry = {
        'status': status,
        'timestamp': current_time,
        # Store the threat details only if malicious, otherwise None
        'threat_details': threat if status == 'malicious' else None
    }
    cache[ip_address] = cache_entry

    return threat # Return the threat dict if malicious, else None