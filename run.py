from src.capture.packet_sniffer import start_sniffer
from src.ui.app import create_app
import threading

if __name__ == "__main__":
    # Create the Flask app
    app = create_app()
    
    # Print registered routes for debugging
    print("Registered routes in run.py:")
    for rule in app.url_map.iter_rules():
        print(f" - {rule}")
    
    # Start the packet sniffer in a separate thread
    sniffer_thread = threading.Thread(target=start_sniffer)
    sniffer_thread.daemon = True
    sniffer_thread.start()
    
    # Run the web UI
    app.run(host="127.0.0.1", port=5000, debug=True)
