from lib.core import app, sniffer_thread
import threading
import sys
import os

if __name__ == "__main__":
    try:
        # Pre-check permission only if we really want to sniff
        # Note: lib.core handles the fallback to demo mode gracefully
        pass 
    except KeyboardInterrupt:
        sys.exit(0)
    
    port = int(os.environ.get("PORT", 5001))
    app.run(host='0.0.0.0', port=port)
