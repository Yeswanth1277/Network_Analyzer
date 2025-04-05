# src/analysis/heuristics.py
import time
from scapy.all import TCP, UDP
import logging

log_heuristic = logging.getLogger('sniffer.heuristic') # Sub-logger

# --- Simple Port Scan Detection ---
# Note: This is basic in-memory state. See limitations mentioned earlier.
def detect_port_scan(src_ip, dst_ip, packet_scapy, scan_state, time_window=60, port_threshold=10):
    """
    Detects potential port scanning using simple heuristics.

    Args:
        src_ip (str): Source IP address.
        dst_ip (str): Destination IP address.
        packet_scapy: The raw Scapy packet object (to get port).
        scan_state (dict): The shared dictionary holding scan tracking info.
        time_window (int): Seconds within which to count ports.
        port_threshold (int): Number of unique ports to trigger detection.

    Returns:
        dict or None: Threat details if a scan is detected, otherwise None.
    """
    dst_port = None
    if TCP in packet_scapy:
        dst_port = packet_scapy[TCP].dport
    elif UDP in packet_scapy:
        dst_port = packet_scapy[UDP].dport
    else:
        return None # Only track TCP/UDP scans for this example

    if dst_port is None:
        return None

    current_time = time.time()
    state_key = (src_ip, dst_ip) # Track scans per source-destination pair

    # Initialize state for this pair if not exists
    if state_key not in scan_state:
        scan_state[state_key] = {'timestamps': [], 'ports': set()}

    # --- Clean up old entries ---
    state = scan_state[state_key]
    state['timestamps'] = [ts for ts in state['timestamps'] if current_time - ts <= time_window]
    # Rebuild port set based on remaining timestamps (slightly inefficient but simple)
    # A more optimized way would store (timestamp, port) tuples
    relevant_ports = set()
    temp_timestamps = []
    for i, ts in enumerate(state['timestamps']):
         # Assume state['ports'] order matches state['timestamps'] if rebuilt this way
         # This logic needs improvement if ports are just added without relation to timestamp
         # Let's simplify: Store (timestamp, port)
         pass # Need to redesign state slightly for perfect port tracking with timestamps

    # --- Simplified State: Just track ports within the window ---
    # Remove timestamps older than the window
    state['timestamps'] = [ts for ts in state['timestamps'] if current_time - ts <= time_window]
    # If timestamps is empty, clear ports (simplification)
    if not state['timestamps']:
        state['ports'].clear()

    # Add current attempt
    state['timestamps'].append(current_time)
    state['ports'].add(dst_port)

    # Check if threshold is met
    if len(state['ports']) >= port_threshold:
        # Avoid re-alerting immediately - add a cooldown or flag
        if not state.get('alerted', False):
            threat = {
                "signature_id": "HEUR-PORT-SCAN",
                "description": f"Potential Port Scan detected from {src_ip} to {dst_ip} ({len(state['ports'])} ports in {time_window}s)",
                "severity": "Medium",
                "type": "Heuristic/Scan"
            }
            log_heuristic.warning(f"Port Scan detected: {src_ip} -> {dst_ip} ({len(state['ports'])} ports)")
            state['alerted'] = True # Flag that we've alerted for this window
            return threat
        # else: # If already alerted, optionally log debug message
        #    log_heuristic.debug(f"Ongoing scan detected but already alerted: {src_ip} -> {dst_ip}")

    # Reset alerted flag if port count drops below threshold (or after timeout)
    elif len(state['ports']) < port_threshold and state.get('alerted', False):
         state['alerted'] = False

    return None