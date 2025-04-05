from scapy.all import sniff, IP, TCP, UDP, PcapWriter, conf as scapy_conf
from src.utils.db_handler import save_packet
from src.analysis.geolocation import get_geolocation
# --- IMPORT YOUR DETECTION FUNCTIONS ---
from src.analysis.threat_detection import detect_threat # Existing signature-based
from src.analysis.protocol_anomaly import detect_protocol_anomaly
from src.analysis.heuristics import detect_port_scan
from src.analysis.reputation import check_ip_reputation
# --- State Management Imports ---
import time # Needed for heuristics/caching potentially
import os
import logging
import sys
import platform

# ---- Scapy Verbosity (Optional: Uncomment for deep Scapy debugging) ----
# logging.getLogger("scapy.runtime").setLevel(logging.DEBUG)
# logging.getLogger("scapy.interactive").setLevel(logging.DEBUG)
# -----------------------------------------------------------------------

PCAP_FILE = os.path.abspath("data/captured_packets.pcap")
LOG_DIR = os.path.abspath("data/logs")

os.makedirs(os.path.dirname(PCAP_FILE), exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

# Configure basic logging for the sniffer module and submodules
log_sniffer = logging.getLogger('sniffer')
log_sniffer.setLevel(logging.INFO) # Set default level
# --- File Handler for Sniffer ---
log_formatter = logging.Formatter('%(asctime)s - [%(name)s] - [%(levelname)s] - %(message)s')
file_handler_sniff = logging.FileHandler(os.path.join(LOG_DIR, "sniffer.log"))
file_handler_sniff.setFormatter(log_formatter)
log_sniffer.addHandler(file_handler_sniff)
# --- Stream Handler (Console) ---
# Check if a StreamHandler already exists to avoid duplicate console logs
if not any(isinstance(h, logging.StreamHandler) for h in log_sniffer.handlers):
    stream_handler_sniff = logging.StreamHandler(sys.stdout)
    stream_handler_sniff.setFormatter(log_formatter)
    log_sniffer.addHandler(stream_handler_sniff)
# -----------------------------------


# --- PCAP Writer Setup ---
pcap_writer = None
try:
    # Ensure the file exists before opening in append mode with PcapWriter
    if not os.path.exists(PCAP_FILE):
        open(PCAP_FILE, 'w').close() # Create file if it doesn't exist
    elif os.path.getsize(PCAP_FILE) == 0:
         # If file exists but is empty, PcapWriter append might need header
         pass # PcapWriter append=True should handle this, but watch out

    pcap_writer = PcapWriter(PCAP_FILE, append=True, sync=True)
    log_sniffer.info(f"PCAP writer initialized for {PCAP_FILE}")
except Exception as e:
    log_sniffer.error(f"Failed to initialize PCAP writer for {PCAP_FILE}: {e}", exc_info=True)
    pcap_writer = None

# --- State Management Dictionaries (In-Memory - See Limitations) ---
SCAN_DETECTION_STATE = {} # Tracks port scan attempts { ('src','dst'): {'timestamps':[], 'ports':set(), 'alerted': bool} }
IP_REPUTATION_CACHE = {} # Caches IP reputation lookup results { 'ip': {'status': str, 'timestamp': float, 'threat_details': dict/None} }

def get_highest_severity_threat(threats):
    """Helper to choose the threat with the highest severity from a list."""
    if not threats:
        return None

    severity_order = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Informational": 1, "Unknown": 0}

    sorted_threats = sorted(
        threats,
        key=lambda t: severity_order.get(t.get('severity', 'Unknown'), 0),
        reverse=True
    )
    log_sniffer.debug(f"Prioritized threats: {[t.get('signature_id') for t in sorted_threats]}")
    return sorted_threats[0]

def packet_callback(packet):
    """Processes each captured packet, performs analysis, saves with threat info."""
    global pcap_writer, SCAN_DETECTION_STATE, IP_REPUTATION_CACHE
    log_sniffer.info(f"--- Processing packet: {packet.summary()} ---") # Log entry

    try:
        # --- Inner Try-Except for detailed logging within the main processing ---
        try:
            if not packet.haslayer(IP):
                log_sniffer.debug("Packet does not have IP layer, skipping.")
                return

            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            proto_num = packet[IP].proto

            log_sniffer.debug(f"Getting GeoIP for {src_ip} and {dst_ip}")
            src_geo = get_geolocation(src_ip)
            dst_geo = get_geolocation(dst_ip)

            data = {
                "src_ip": src_ip, "dst_ip": dst_ip, "src_geo": src_geo,
                "dst_geo": dst_geo, "protocol": proto_num,
                "payload": bytes(packet.payload).hex(),
                "threat_id": None, "threat_description": None, "threat_severity": None
            }

            # --- Run All Detection Methods ---
            detected_threats_list = []
            log_sniffer.debug("Running detection methods...")

            # 1. Signature-Based Detection
            try:
                sig_threat = detect_threat(packet, data)
                if sig_threat: detected_threats_list.append(sig_threat)
            except Exception as e: log_sniffer.error(f"Error in signature detection: {e}", exc_info=False)

            # 2. Protocol Anomaly Detection
            try:
                proto_threat = detect_protocol_anomaly(packet)
                if proto_threat: detected_threats_list.append(proto_threat)
            except Exception as e: log_sniffer.error(f"Error in protocol anomaly: {e}", exc_info=False)

            # 3. Heuristic: Port Scan Detection
            try:
                scan_threat = detect_port_scan(src_ip, dst_ip, packet, SCAN_DETECTION_STATE)
                if scan_threat: detected_threats_list.append(scan_threat)
            except Exception as e: log_sniffer.error(f"Error in port scan detection: {e}", exc_info=False)

            # 4. Reputation Check (Source IP)
            try:
                src_rep_threat = check_ip_reputation(src_ip, IP_REPUTATION_CACHE)
                if src_rep_threat: detected_threats_list.append(src_rep_threat)
            except Exception as e: log_sniffer.error(f"Error in src IP reputation: {e}", exc_info=False)

            # 5. Reputation Check (Destination IP)
            try:
                dst_rep_threat = check_ip_reputation(dst_ip, IP_REPUTATION_CACHE)
                if dst_rep_threat: detected_threats_list.append(dst_rep_threat)
            except Exception as e: log_sniffer.error(f"Error in dst IP reputation: {e}", exc_info=False)

            log_sniffer.debug(f"Found {len(detected_threats_list)} potential threats.")

            # --- Prioritize and Finalize Threat Info ---
            final_threat = get_highest_severity_threat(detected_threats_list)
            if final_threat:
                data["threat_id"] = final_threat.get("signature_id", "N/A")
                data["threat_description"] = final_threat.get("description", "N/A")
                data["threat_severity"] = final_threat.get("severity", "Unknown")
                log_sniffer.info(f"Highest severity threat for packet {src_ip}->{dst_ip}: ID={data['threat_id']}, Sev={data['threat_severity']}")

            # --- Save Packet ---
            log_sniffer.debug(f"Calling save_packet for {src_ip} -> {dst_ip}")
            save_packet(data)
            log_sniffer.debug(f"Finished save_packet for {src_ip} -> {dst_ip}")

            # --- Save to PCAP file ---
            if pcap_writer:
                log_sniffer.debug(f"Calling pcap_writer.write for {src_ip} -> {dst_ip}")
                pcap_writer.write(packet)
                log_sniffer.debug(f"Finished pcap_writer.write for {src_ip} -> {dst_ip}")
            else:
                 log_sniffer.warning("PCAP writer is None, cannot write packet.")

        except Exception as inner_e:
            log_sniffer.error(f"!!!!!! INNER EXCEPTION in packet_callback: {inner_e} !!!!!!", exc_info=True)

    # --- Outer Exception Handler ---
    except AttributeError as ae:
        log_sniffer.warning(f"Attribute error processing packet (likely malformed): {ae} - Packet summary: {packet.summary()}")
    except Exception as outer_e:
        log_sniffer.error(f"!!!!!! OUTER EXCEPTION in packet_callback: {outer_e} - Packet: {packet.summary()} !!!!!!", exc_info=True)
    finally:
        log_sniffer.info(f"--- Finished processing packet: {packet.summary()} ---") # Log exit


# --- Function to determine default loopback interface name ---
def get_loopback_interface():
    system = platform.system()
    if system == "Linux": return "lo"
    if system == "Darwin": return "lo0"
    if system == "Windows":
        log_sniffer.warning("Attempting automatic loopback detection on Windows. Ensure Npcap with loopback support is installed.")
        try:
            from scapy.arch.windows import get_windows_if_list
            interfaces = get_windows_if_list()
            for iface in interfaces:
                desc = iface.get('description', '').lower()
                # Prefer description match for loopback on Windows
                if 'loopback' in desc:
                    log_sniffer.info(f"Found Windows loopback by description: '{iface.get('description')}'")
                    return iface.get('description') # Return the description Scapy uses
            log_sniffer.warning("Could not identify loopback interface via Scapy description on Windows. Check Npcap installation.")
        except ImportError: log_sniffer.warning("Cannot import Scapy's Windows functions to find loopback.")
        except Exception as e: log_sniffer.warning(f"Error trying to find Windows loopback interface via Scapy: {e}")
        return None
    log_sniffer.warning(f"Unsupported OS for automatic loopback detection: {system}. Defaulting to None.")
    return None

LOOPBACK_IF = get_loopback_interface()
log_sniffer.info(f"Determined loopback interface for this system: '{LOOPBACK_IF}'")

# --- Start Sniffer Function ---
def start_sniffer(interface=LOOPBACK_IF):
    """Starts the packet sniffer on the specified interface."""
    global pcap_writer

    # --- Interface Selection Logic ---
    if interface:
        log_sniffer.info(f"Starting packet sniffer on specified interface: '{interface}'...")
    elif LOOPBACK_IF:
        log_sniffer.warning("--- STARTING IN FORCED LOOPBACK MODE (DEFAULT) ---")
        interface = LOOPBACK_IF # Use detected loopback if interface is None
    else:
        log_sniffer.info(f"Starting packet sniffer on default interface (Scapy chooses)...")
        # Scapy will try to pick one if interface remains None

    # --- Check if interface is actually set before proceeding ---
    if not interface:
         log_sniffer.error("No interface available or specified. Cannot start sniffer.")
         print("ERROR: No network interface specified or detected. Exiting sniffer thread.", file=sys.stderr)
         return # Stop the thread if no interface is determined

    log_sniffer.info(f"Threat detection methods active: Signatures, Protocol Anomaly, Heuristics, IP Reputation.")
    log_sniffer.info(f"Threat logs in: {os.path.join(LOG_DIR, 'threats.log')} (if configured by signature detection)")
    if pcap_writer:
        log_sniffer.info(f"Saving raw packets to PCAP: {PCAP_FILE}")
    else:
        log_sniffer.warning("PCAP writing is disabled.")

    try:
        from src.analysis.threat_detection import load_signatures
        log_sniffer.info("Loading threat signatures...")
        load_signatures()

        sniff_options = {"prn": packet_callback, "store": False, "iface": interface}
        # Note: Removed the 'if interface:' check here as we ensure interface is set above

        log_sniffer.info(f"Starting sniff operation with options: {sniff_options}")
        print(f"Sniffer thread trying to start sniffing on: {interface}") # Console print

        # === Explicit Try/Except around sniff() ===
        try:
            # Using stop_filter can sometimes be more reliable than relying on Ctrl+C in threads
            # def should_stop_sniffing(pkt): return False # Replace with actual stop condition if needed
            # sniff(stop_filter=should_stop_sniffing, **sniff_options)

            sniff(**sniff_options) # Normal blocking call

            # This line should ideally only be reached if sniff is stopped gracefully
            log_sniffer.warning("Sniff function returned without error. Sniffer likely stopped.")
            print("Sniffer thread: sniff() function finished.") # Console print
        except Exception as sniff_err:
            log_sniffer.error(f"!!!!! EXCEPTION DURING sniff() CALL: {sniff_err} !!!!!", exc_info=True)
            print(f"Sniffer thread ERROR during sniff(): {sniff_err}") # Console print
        # ==========================================

    except OSError as e:
         if "permitted" in str(e).lower() or "denied" in str(e).lower():
             log_sniffer.error(f"Permission Error starting sniffer on interface '{interface}': {e}. Try sudo/admin.")
             print(f"Sniffer thread PERMISSION ERROR: {e}. Run as Administrator.")
         else:
            log_sniffer.error(f"OS Error starting sniffer (interface='{interface}'): {e}.", exc_info=True)
            print(f"Sniffer thread OS ERROR: {e}")
    except ImportError as e:
        log_sniffer.error(f"Import error during sniffing setup: {e}.", exc_info=True)
        print(f"Sniffer thread IMPORT ERROR: {e}")
    except Exception as e:
        log_sniffer.error(f"An unexpected error occurred in start_sniffer: {e}", exc_info=True)
        print(f"Sniffer thread UNEXPECTED ERROR: {e}")
    finally:
        if pcap_writer:
            try:
                log_sniffer.info("Attempting to close PCAP writer...")
                # Check if close method exists and call it
                if hasattr(pcap_writer, 'close') and callable(pcap_writer.close):
                     pcap_writer.close()
                     log_sniffer.info("PCAP writer closed.")
                else:
                     log_sniffer.warning("PCAP writer object does not have a callable close method.")
            except Exception as e:
                log_sniffer.error(f"Error closing PCAP writer: {e}", exc_info=True)
        log_sniffer.info("Sniffer thread finished.")
        print("Sniffer thread has finished.") # Console print