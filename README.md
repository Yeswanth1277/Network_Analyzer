  Advanced Network Security Monitoring System with Threat Detection

  Overview

This project is a Python-based network security monitoring tool designed to capture network packets in real-time, analyze them using multiple detection techniques, and visualize potential threats on a web-based dashboard. It serves as a practical implementation of core intrusion detection concepts.

The system utilizes Scapy for packet capture and manipulation, Flask for the web UI, and SQLite for data persistence. Threat detection incorporates signature matching, protocol anomaly checks, heuristic analysis (port scan detection), and IP reputation lookups via the AbuseIPDB API. Geolocation data is added using the GeoLite2 database.

  Key Features

     Real-Time Packet Capture:  Captures live network traffic using Scapy.
     Multi-Method Threat Analysis: 
         Signature-Based:  Matches packet payloads against predefined patterns in `basic_threats.json`.
         Protocol Anomaly:  Detects violations like TCP Xmas/Null scans.
         Heuristics:  Identifies potential port scanning behavior.
         IP Reputation:  Checks source/destination IPs against AbuseIPDB (requires API key).
     Geolocation Enrichment:  Adds geographic context (City, Country) to IP addresses using a local GeoLite2 database.
     Threat Prioritization:  Selects the highest severity threat if multiple are detected for a single packet.
     Data Persistence:  Stores analyzed packet details and threat information in an SQLite database (`packets.db`).
     PCAP Logging:  Saves raw captured packets to a `.pcap` file (`captured_packets.pcap`) for offline analysis.
     Web Dashboard:  Provides a dynamic UI built with Flask:
        Displays captured packets with near real-time updates.
        Visually highlights detected threats based on severity.
        Allows filtering packets by protocol.
        Offers a download button for the captured PCAP file.
     Modular Design:  Code structured into distinct components for capture, analysis, database interaction, and UI.

  Architecture

The system operates with two main threads:
1.   Sniffer Thread:  Captures packets using Scapy, runs them through the analysis pipeline (geolocation, signatures, anomalies, heuristics, reputation), prioritizes threats, and saves results to the database and PCAP file.
2.   Main Thread:  Runs the Flask web server, serving the UI and handling API requests to fetch data from the database or provide the PCAP download.

 (Optional: You can embed or link to the architecture diagram image here if you add it to your repository) 

  Directory Structure (`data/` Folder)

The application relies on a specific structure within the `data/` directory. You will need to create some of these directories and files yourself.

Files/Folders to Create/Provide in `data/`:

1.   `data/geoip/` (Directory):  Create this directory.
2.   `data/geoip/GeoLite2-City.mmdb` (File):  Download the free GeoLite2 City database from MaxMind ([https://dev.maxmind.com/geoip/geolite2-free-geolocation-data](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)) and place the `.mmdb` file here. You might need to sign up for a free account.
3.   `data/signatures/` (Directory):  Create this directory.
4.   `data/signatures/basic_threats.json` (File):  Create this JSON file to hold your threat signatures. See the example structure below.

 Example `basic_threats.json` structure: 

```json
[
  {
    "signature_id": "SIG-001",
    "description": "Potential SQL Injection Attempt (SELECT  )",
    "pattern": "SELECT\\s+\\ \\s+FROM",
    "severity": "High",
    "type": "Web Attack",
    "protocol": "TCP",
    "port": [80, 443, 8080]
  },
  {
    "signature_id": "SIG-002",
    "description": "Potential Shell Command Injection (cat /etc/passwd)",
    "pattern": "cat\\s+/etc/passwd",
    "severity": "Critical",
    "type": "Command Injection"
  }
]

(Note: protocol and port are optional filters in the signature.)

Setup and Installation
Prerequisites:

Python: Version 3.8+ recommended.

Operating System: Tested primarily on Windows, but should work on Linux/macOS with appropriate dependencies.

Packet Capture Library:

Windows: Npcap is required. Download and install from npcap.com. Crucially, ensure "Install Npcap in WinPcap API-compatible Mode" is CHECKED during installation.

Linux: libpcap-dev (e.g., sudo apt-get install libpcap-dev)

macOS: libpcap is usually included.

Administrator/sudo Privileges: Required for packet capture.

Installation Steps:

Clone the Repository:

git clone <your-repository-url>
cd net-tool

Bash
Create requirements.txt:
Create a file named requirements.txt in the project root (net-tool/) with the following content (adjust versions if needed):

Flask>=2.0
scapy>=2.4.5
geoip2>=4.1.0
requests>=2.25.0

Txt
Install Python Dependencies:
It's recommended to use a virtual environment:

python -m venv venv
  Activate the virtual environment
  Windows:
.\venv\Scripts\activate
  Linux/macOS:
  source venv/bin/activate

  Install requirements
pip install -r requirements.txt

Bash
Download GeoLite2 Database:
Download the GeoLite2-City.mmdb file from MaxMind (see link in "Directory Structure" section) and place it inside the data/geoip/ directory.

Create Signature File:
Create the data/signatures/ directory and the data/signatures/basic_threats.json file with your desired threat signatures (use the example structure above as a starting point).

Set API Key (Optional but Recommended):
For IP reputation checking, obtain a free API key from AbuseIPDB. Set it as an environment variable:

  Windows (Command Prompt)
set ABUSEIPDB_API_KEY=YOUR_API_KEY_HERE

  Windows (PowerShell)
$env:ABUSEIPDB_API_KEY="YOUR_API_KEY_HERE"

  Linux/macOS
export ABUSEIPDB_API_KEY=YOUR_API_KEY_HERE

Bash
(Note: You might need to set this persistently depending on your system.) If the key is not set, reputation checks will be skipped.

Running the Application
Open Terminal as Administrator: Right-click your terminal (Command Prompt, PowerShell, etc.) and select "Run as administrator" (or use sudo on Linux/macOS).

Navigate to Project Root:

cd path/to/your/net-tool

Bash
Activate Virtual Environment (if you created one):

  Windows:
.\venv\Scripts\activate
  Linux/macOS:
  source venv/bin/activate

Bash
Run the Application:
Use the -m flag to run run as a module, which helps Python resolve imports correctly:

python -m run
Bash
Access the Web UI: Open your web browser and go to http://127.0.0.1:5000.

The sniffer will start capturing packets on the default loopback interface (or your primary interface if loopback detection fails/isn't supported), analyzing them, and displaying results on the web dashboard.

Usage
Dashboard: View incoming packets, including source/destination IPs, ports, protocols, geolocation, and payload snippets.

Threat Highlighting: Rows corresponding to packets flagged with threats will be visually highlighted (e.g., colored background, border) based on severity. Threat details (ID, description, severity) will be shown in the respective columns.

Filtering: Use the input box at the top to filter displayed packets by protocol name (e.g., TCP, UDP, ICMP). Press "Apply Filter". Use "Clear Filter" to reset.

Download PCAP: Click the "Download PCAP" button to download the data/captured_packets.pcap file containing all raw packets captured during the session.

Contributing
Contributions are welcome! Please feel free to submit pull requests or open issues for bugs or feature suggestions.

License
(Choose a license, e.g., MIT, Apache 2.0)
This project is licensed under the MIT License - see the LICENSE file for details. (You'll need to create a LICENSE file)

---

 Remember to: 

1.  Replace `<your-repository-url>` with the actual URL.
2.  Create the `requirements.txt` file as specified.
3.  Create the necessary `data/` subdirectories and the `basic_threats.json` file.
4.  Download the `GeoLite2-City.mmdb` file.
5.  Choose and add a `LICENSE` file to your repository.
