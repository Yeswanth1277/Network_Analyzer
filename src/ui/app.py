from flask import Flask, render_template, jsonify, request, send_file
from src.utils.db_handler import fetch_packets
import os

def create_app():
    app = Flask(__name__)

    @app.route("/")
    def dashboard():
        return render_template("index.html")

    @app.route("/packets")
    def packets():
        protocol = request.args.get("protocol")
        packets_data = fetch_packets(protocol=protocol)
        return jsonify(packets_data)

    @app.route("/download_pcap")
    def download_pcap():
        pcap_path = "data/captured_packets.pcap"
        app_root = os.path.dirname(os.path.abspath(__file__))
        full_path = os.path.join(app_root, "..", "..", pcap_path)
        
        print(f"[DEBUG] Looking for PCAP at: {full_path}")
        
        if os.path.exists(full_path):
            print(f"[INFO] Sending PCAP file: {full_path}")
            return send_file(full_path, as_attachment=True)
        else:
            print(f"[ERROR] PCAP file not found at: {full_path}")
            return "PCAP file not found", 404

    # Debug: Print all routes
    print("Routes registered:")
    for rule in app.url_map.iter_rules():
        print(f" - {rule}")
            
    return app