# src/utils/db_handler.py

import sqlite3
import os
import logging

# Configure logging for this module
log = logging.getLogger('db_handler')
log.setLevel(logging.INFO) # Default level
if not log.hasHandlers():
    log_formatter = logging.Formatter('%(asctime)s - [%(name)s] - [%(levelname)s] - %(message)s')
    log_dir = os.path.abspath("data/logs")
    os.makedirs(log_dir, exist_ok=True)
    file_handler = logging.FileHandler(os.path.join(log_dir, "database.log"))
    file_handler.setFormatter(log_formatter)
    log.addHandler(file_handler)
    # import sys
    # stream_handler = logging.StreamHandler(sys.stdout)
    # stream_handler.setFormatter(log_formatter)
    # log.addHandler(stream_handler)


# Path to the SQLite database - Use absolute path for reliability
DB_PATH = os.path.abspath("data/packets.db")

def create_tables():
    """
    Creates the necessary database tables for storing packet information,
    including threat details.
    Ensures the 'data' directory exists before creating the database.
    """
    log.info(f"Database path configured: {DB_PATH}")

    data_dir = os.path.dirname(DB_PATH)
    if not os.path.exists(data_dir):
        try:
            log.info(f"'data/' directory not found at {data_dir}. Creating it now...")
            os.makedirs(data_dir)
            log.info(f"'data/' directory created successfully at {data_dir}.")
        except Exception as e:
            log.error(f"Failed to create 'data/' directory at {data_dir}: {e}")
            return

    conn = None
    try:
        log.info(f"Attempting to connect to the database: {DB_PATH}")
        conn = sqlite3.connect(DB_PATH, timeout=10)
        log.info("Connected to the database successfully!")

        log.info("Ensuring 'packets' table exists and has the correct schema...")
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                src_ip TEXT NOT NULL,
                dst_ip TEXT NOT NULL,
                src_city TEXT,
                src_country TEXT,
                dst_city TEXT,
                dst_country TEXT,
                protocol TEXT NOT NULL,
                payload TEXT,
                threat_id TEXT,
                threat_description TEXT,
                threat_severity TEXT
            )
        """)
        conn.commit()
        log.info("Database table 'packets' checked/created successfully!")

    except sqlite3.OperationalError as e:
        log.error(f"SQLite operational error during table creation (database might be locked?): {e}")
    except sqlite3.Error as e:
        log.error(f"SQLite error occurred during table creation: {e}")
    except Exception as e:
        log.error(f"An unexpected error occurred during table creation: {e}")
    finally:
        if conn:
            try:
                conn.close()
                log.info("Database connection closed after table creation check.")
            except sqlite3.Error as e:
                log.error(f"Error closing database connection after table creation: {e}")

def get_protocol_name(proto_num):
    """Converts common IP protocol numbers to their names."""
    if not isinstance(proto_num, int):
        return str(proto_num)

    protocol_map = {
        1: "ICMP", 6: "TCP", 17: "UDP", 2: "IGMP", 89: "OSPF",
    }
    return protocol_map.get(proto_num, str(proto_num))

def save_packet(packet):
    """
    Saves a processed packet dictionary to the database.
    Expects the protocol number in packet['protocol'].
    Converts protocol number to name before saving.
    Includes prioritized threat information if present.

    Args:
        packet (dict): A dictionary containing packet details including:
            src_ip, dst_ip, src_geo (dict), dst_geo (dict),
            protocol (int), payload (hex string),
            threat_id (str, optional), threat_description (str, optional),
            threat_severity (str, optional).
    """
    conn = None
    required_keys = ["src_ip", "dst_ip", "src_geo", "dst_geo", "protocol", "payload"]
    if not all(key in packet for key in required_keys):
        log.error(f"Packet dictionary missing required keys for saving. Data: {packet}")
        return
    if not isinstance(packet.get("src_geo"), dict) or not isinstance(packet.get("dst_geo"), dict):
         log.error(f"Packet geo information is not a dictionary or missing. Data: {packet}")
         # Provide default geo if missing to avoid breaking insertion
         packet.setdefault("src_geo", {"city": "Unknown", "country": "Unknown"})
         packet.setdefault("dst_geo", {"city": "Unknown", "country": "Unknown"})
         # return # Or decide to proceed with default geo

    try:
        protocol_name = get_protocol_name(packet["protocol"])
        # Safely get geo info, using defaults from the packet dict if needed
        src_city = packet["src_geo"].get("city", "Unknown")
        src_country = packet["src_geo"].get("country", "Unknown")
        dst_city = packet["dst_geo"].get("city", "Unknown")
        dst_country = packet["dst_geo"].get("country", "Unknown")

        # Get threat info, defaulting to None if not present in packet dict
        threat_id = packet.get("threat_id")
        threat_desc = packet.get("threat_description")
        threat_sev = packet.get("threat_severity")

        conn = sqlite3.connect(DB_PATH, timeout=10)
        cursor = conn.cursor()

        sql = """
            INSERT INTO packets (
                src_ip, dst_ip, src_city, src_country,
                dst_city, dst_country, protocol, payload,
                threat_id, threat_description, threat_severity
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) -- 11 placeholders
        """
        params = (
            packet["src_ip"], packet["dst_ip"],
            src_city, src_country,
            dst_city, dst_country,
            protocol_name,
            packet["payload"],
            # Add threat parameters (will be None if no threat was prioritized)
            threat_id,
            threat_desc,
            threat_sev
        )

        cursor.execute(sql, params)
        conn.commit()
        log.debug(f"Packet from {packet['src_ip']} to {packet['dst_ip']} ({protocol_name}) saved.")
        # Log specifically if a threat was associated with the saved packet
        if threat_id:
            log.info(f"Saved packet flagged with threat: ID={threat_id}, Severity={threat_sev}, Src={packet['src_ip']}")

    except sqlite3.OperationalError as e:
        log.error(f"SQLite operational error saving packet (database might be locked?): {e} - Data: {packet.get('src_ip', 'N/A')}->{packet.get('dst_ip', 'N/A')}")
    except sqlite3.Error as e:
        log.error(f"Failed to save packet to the database: {e} - Data: {packet.get('src_ip', 'N/A')}->{packet.get('dst_ip', 'N/A')}")
    except KeyError as e:
        log.error(f"Missing key in packet data during save: {e} - Data: {packet}")
    except Exception as e:
        log.error(f"An unexpected error occurred during packet save: {e} - Data: {packet.get('src_ip', 'N/A')}->{packet.get('dst_ip', 'N/A')}")
    finally:
        if conn:
            try:
                conn.close()
            except sqlite3.Error as e:
                log.error(f"Error closing database connection after packet save: {e}")


def fetch_packets(protocol=None):
    """
    Fetches packets from the database, optionally filtering by protocol name.
    Formats the results including nested geo objects and threat info.
    *** PRIORITIZES packets with threats, sorting them by severity, then by ID DESC. ***

    Args:
        protocol (str, optional): Protocol name to filter by. Defaults to None.

    Returns:
        list: A list of dictionaries, each representing a packet. Returns empty list on error.
    """
    conn = None
    packets_list = []
    try:
        conn = sqlite3.connect(DB_PATH, timeout=10)
        # Use dictionary row factory for easier access by column name
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Base query selecting all necessary columns
        query = """
            SELECT id, src_ip, dst_ip, src_city, src_country,
                   dst_city, dst_country, protocol, payload,
                   threat_id, threat_description, threat_severity
            FROM packets
            WHERE 1=1
        """
        params = []

        # Add protocol filter if provided
        if protocol:
            protocol_str = str(protocol).strip().upper()
            if protocol_str:
                query += " AND upper(protocol) = ?"
                params.append(protocol_str)

        # --- MODIFIED ORDER BY Clause ---
        # 1. Prioritize rows that HAVE a threat_id (threats come first)
        # 2. Within threats, sort by severity (e.g., High > Medium > Low)
        # 3. As a final tie-breaker, sort by packet ID descending (most recent first)
        query += """
            ORDER BY
                CASE WHEN threat_id IS NOT NULL THEN 0 ELSE 1 END ASC, -- Puts threats (0) before non-threats (1)
                CASE threat_severity
                    WHEN 'Critical' THEN 5  -- Assign numerical values for sorting
                    WHEN 'High' THEN 4
                    WHEN 'Medium' THEN 3
                    WHEN 'Low' THEN 2
                    WHEN 'Informational' THEN 1
                    ELSE 0                  -- Unknown/None severity lowest priority within threats
                END DESC,                   -- Higher severity number comes first
                id DESC                     -- Most recent packets first among equals
            LIMIT 200                       -- Keep the limit
        """
        # --- End MODIFIED ORDER BY ---

        log.debug(f"Executing query: {query} with params: {params}")
        cursor.execute(query, params)
        rows = cursor.fetchall()

        for row in rows:
            packet_dict = dict(row) # Convert Row to dict for easier manipulation

            # Create nested geo dicts
            packet_dict['src_geo'] = {
                "city": packet_dict.pop('src_city', 'Unknown'),
                "country": packet_dict.pop('src_country', 'Unknown')
            }
            packet_dict['dst_geo'] = {
                "city": packet_dict.pop('dst_city', 'Unknown'),
                "country": packet_dict.pop('dst_country', 'Unknown')
            }
            # Ensure threat keys exist, even if NULL in DB (becomes None here)
            packet_dict.setdefault('threat_id', None)
            packet_dict.setdefault('threat_description', None)
            packet_dict.setdefault('threat_severity', None)

            packets_list.append(packet_dict)

        log.info(f"Fetched {len(packets_list)} packets from DB" + (f" matching protocol '{protocol}'." if protocol else ".") + " (Threats prioritized)")

    except sqlite3.OperationalError as e:
        log.error(f"SQLite operational error fetching packets (database might be locked?): {e}")
        packets_list = []
    except sqlite3.Error as e:
        log.error(f"Failed to fetch packets from the database: {e}")
        packets_list = []
    except Exception as e:
        log.error(f"An unexpected error occurred during packet fetch: {e}")
        packets_list = []
    finally:
        if conn:
            try:
                conn.close()
            except sqlite3.Error as e:
                log.error(f"Error closing database connection after packet fetch: {e}")

    return packets_list


# # --- Optional: Testing block ---
# if __name__ == "__main__":
#     # Configure logging just for this test run if needed
#     # logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - [%(name)s] - [%(levelname)s] - %(message)s')
#     # log.setLevel(logging.DEBUG)

#     print("Running DB Handler directly for testing...")
#     create_tables()

#     # Add some dummy data if needed for testing the sort order
#     # ... save_packet calls with and without threats of different severities ...

#     print("\nFetching all packets (Threats should be first):")
#     all_packets = fetch_packets()
#     print(f"Fetched {len(all_packets)} packets.")
#     if all_packets:
#         print("First 10 packets (or fewer):")
#         for i, p in enumerate(all_packets[:10]): # Print first 10
#             print(f"  {i+1}: ID={p['id']}, ThreatID={p.get('threat_id', '-')}, Sev={p.get('threat_severity', '-')}")

#     print("\nDB Handler test finished.")