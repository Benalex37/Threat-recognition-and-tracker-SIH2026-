import os
import uvicorn
from app.main import app
from app.config import load_config, DEFAULT_PORT

if __name__ == "__main__":
    config = load_config()
    # ETD_PORT wins so a second instance can be started without editing config.
    port = int(os.environ.get("ETD_PORT") or config.get("local_port", DEFAULT_PORT))
    os.environ["ETD_ACTIVE_PORT"] = str(port)
    print(f"\n  TrT — Threat Recognition and Tracker")
    print(f"  Engine    -> http://127.0.0.1:{port}")
    print(f"  Dashboard -> http://127.0.0.1:{port}/dashboard\n")
    uvicorn.run(app, host="127.0.0.1", port=port)
