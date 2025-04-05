# src/analysis/threat_detection.py
import json
import re
import logging
import os
from scapy.all import TCP, UDP # Import packet layers

# Configure logging for detected threats
LOG_DIR = "data/logs"
os.makedirs(LOG_DIR, exist_ok=True)
logging.basicConfig(
    filename=os.path.join(LOG_DIR, "threats.log"),
    level=logging.WARNING, # Log warnings and above
    format="%(asctime)s - THREAT DETECTED - %(message)s"
)

SIGNATURE_FILE = "data/signatures/basic_threats.json"
THREAT_SIGNATURES = [] # Cache for loaded signatures

def load_signatures(file_path=SIGNATURE_FILE):
    """Load threat signatures from a JSON file."""
    global THREAT_SIGNATURES
    if not os.path.exists(file_path):
        logging.error(f"Signature file not found: {file_path}")
        THREAT_SIGNATURES = []
        return

    try:
        with open(file_path, "r") as f:
            THREAT_SIGNATURES = json.load(f)
        logging.info(f"Successfully loaded {len(THREAT_SIGNATURES)} signatures from {file_path}")
    except json.JSONDecodeError:
        logging.error(f"Failed to decode JSON from signature file: {file_path}")
        THREAT_SIGNATURES = []
    except Exception as e:
        logging.error(f"Error loading signature file {file_path}: {e}")
        THREAT_SIGNATURES = []

def check_protocol_port(signature, packet_scapy):
    """Check if packet protocol/port matches signature requirements."""
    sig_proto = signature.get("protocol")
    sig_ports = signature.get("port")

    # If no protocol specified in signature, it applies to all protocols
    if not sig_proto:
        return True

    proto_match = False
    packet_dst_port = None

    # Check TCP
    if sig_proto.upper() == "TCP" and TCP in packet_scapy:
        proto_match = True
        if sig_ports:
            packet_dst_port = packet_scapy[TCP].dport
    # Check UDP
    elif sig_proto.upper() == "UDP" and UDP in packet_scapy:
        proto_match = True
        if sig_ports:
            packet_dst_port = packet_scapy[UDP].dport
    # Add other protocols (ICMP etc.) here if needed

    if not proto_match:
        return False # Packet protocol doesn't match signature requirement

    # If protocol matches and no specific ports are required by the signature
    if not sig_ports:
        return True

    # If specific ports are required, check if the packet's dest port matches
    if packet_dst_port is not None and packet_dst_port in sig_ports:
        return True

    return False # Port didn't match


def detect_threat(packet_scapy, packet_data):
    """
    Detects threats in packet payloads using signature-based matching.

    Args:
        packet_scapy: The raw Scapy packet object (for protocol/port info).
        packet_data (dict): Dictionary containing extracted packet info, including 'payload' (hex string).

    Returns:
        dict or None: Threat details if detected, otherwise None.
    """
    if not THREAT_SIGNATURES:
        # Attempt to load if cache is empty (e.g., first run)
        load_signatures()
        if not THREAT_SIGNATURES:
            # Still no signatures after attempt, skip detection
            return None

    payload_hex = packet_data.get("payload")
    if not payload_hex:
        return None # No payload to analyze

    try:
        # Decode payload from hex to bytes, then attempt to decode as UTF-8 (best effort)
        payload_bytes = bytes.fromhex(payload_hex)
        payload_text = payload_bytes.decode('utf-8', errors='ignore')
    except ValueError:
        # If payload is not valid hex
        logging.debug(f"Could not decode hex payload for threat detection: {payload_hex[:50]}...")
        payload_text = "" # Cannot analyze non-hex payload as text
        payload_bytes = b"" # Keep bytes empty too
    except Exception as e:
        logging.warning(f"Unexpected error decoding payload: {e}")
        payload_text = ""
        payload_bytes = b""

    detected_threat = None

    for signature in THREAT_SIGNATURES:
        # 1. Check Protocol/Port Filters first (more efficient)
        if not check_protocol_port(signature, packet_scapy):
            continue # Skip this signature if protocol/port doesn't match

        # 2. Check Pattern
        pattern = signature["pattern"]
        try:
            # Search in decoded text first (common for web exploits, scripts)
            # Use re.IGNORECASE for case-insensitivity
            match = re.search(pattern, payload_text, re.IGNORECASE | re.DOTALL)

            # Optional: If no text match, try searching the raw bytes
            # This requires patterns designed for bytes (e.g., hex patterns like r'\x90\x90')
            # if not match and some_condition_to_search_bytes: # e.g., signature['type'] == 'Binary'
            #    match = re.search(pattern.encode('utf-8', errors='ignore'), payload_bytes, re.IGNORECASE | re.DOTALL)

            if match:
                threat_info = {
                    "signature_id": signature["signature_id"],
                    "description": signature["description"],
                    "severity": signature.get("severity", "Unknown"),
                    "type": signature.get("type", "Unknown"),
                    "matched_pattern": pattern,
                    "src_ip": packet_data["src_ip"],
                    "dst_ip": packet_data["dst_ip"],
                    "protocol": packet_data.get("protocol", "N/A"), # Use protocol name if available
                    "payload_snippet": payload_text[max(0, match.start()-20):min(len(payload_text), match.end()+20)].replace('\n',' ').replace('\r','') # Context
                }

                # Log the detected threat (using WARNING level for visibility)
                log_message = (
                    f"Signature: {threat_info['signature_id']} ({threat_info['severity']}) - "
                    f"{threat_info['description']} - "
                    f"Src: {threat_info['src_ip']}, Dst: {threat_info['dst_ip']}, Proto: {threat_info['protocol']} - "
                    f"Snippet: ...{threat_info['payload_snippet']}..."
                )
                logging.warning(log_message)

                # Return the first threat found for this packet
                # More advanced systems might collect all matching threats
                detected_threat = threat_info
                break # Stop after first match for this packet

        except re.error as re_err:
            logging.error(f"Invalid regex pattern in signature {signature.get('signature_id', 'N/A')}: '{pattern}'. Error: {re_err}")
            continue # Skip this invalid pattern
        except Exception as e:
            logging.error(f"Error during regex search for pattern '{pattern}': {e}")
            continue

    return detected_threat

# Load signatures once when the module is imported
load_signatures()