import uvicorn
import os
import sys

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

def main():
    host = os.getenv("AEGIS_HOST", "0.0.0.0")
    port = int(os.getenv("AEGIS_PORT", 8443))
    print(f"[*] Starting AegisShield Central Management Server on http://{host}:{port}")
    uvicorn.run("server.app:app", host=host, port=port, reload=False, log_level="info")

if __name__ == "__main__":
    main()
