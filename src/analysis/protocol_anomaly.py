# src/analysis/protocol_anomaly.py
from scapy.all import TCP
import logging

log_anomaly = logging.getLogger('sniffer.anomaly') # Sub-logger of sniffer

# Define TCP Flags for easier reading
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80

def detect_protocol_anomaly(packet_scapy):
    """
    Checks for basic protocol anomalies in a Scapy packet.

    Args:
        packet_scapy: The raw Scapy packet object.

    Returns:
        dict or None: Threat details if an anomaly is detected, otherwise None.
    """
    threat = None

    if TCP in packet_scapy:
        tcp_layer = packet_scapy[TCP]
        flags = tcp_layer.flags

        # --- Example 1: TCP Xmas Scan ---
        # Detects packets with FIN, PSH, and URG flags set (common scan type)
        if flags & FIN and flags & PSH and flags & URG:
            threat = {
                "signature_id": "ANOM-TCP-XMAS",
                "description": "Potential TCP Xmas Scan detected",
                "severity": "Medium",
                "type": "Protocol Anomaly/Scan"
            }
            log_anomaly.warning(f"Xmas Scan detected: {packet_scapy.summary()}")
            return threat # Return first detected anomaly for this packet for now

        # --- Example 2: TCP Null Scan ---
        # Detects packets with no flags set
        if flags == 0:
             threat = {
                "signature_id": "ANOM-TCP-NULL",
                "description": "Potential TCP Null Scan detected",
                "severity": "Medium",
                "type": "Protocol Anomaly/Scan"
            }
             log_anomaly.warning(f"Null Scan detected: {packet_scapy.summary()}")
             return threat

        # --- Example 3: SYN+FIN Flags Set (Invalid Combination) ---
        if flags & SYN and flags & FIN:
            threat = {
                "signature_id": "ANOM-TCP-SYNFIN",
                "description": "Invalid TCP flags (SYN+FIN) detected",
                "severity": "Low",
                "type": "Protocol Anomaly"
            }
            log_anomaly.warning(f"Invalid SYN+FIN flags: {packet_scapy.summary()}")
            return threat

    # Add checks for UDP, ICMP anomalies here if desired

    return threat # Return None if no anomalies matched