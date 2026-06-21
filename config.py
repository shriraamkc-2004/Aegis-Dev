import os
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

# Event generator settings
EVENT_INTERVAL = float(os.getenv("EVENT_INTERVAL", "0.2"))  # default 200ms
WINDOW_SIZE = int(os.getenv("WINDOW_SIZE", "60"))          # sliding window size (seconds)
Z_SCORE_THRESHOLD = float(os.getenv("Z_SCORE_THRESHOLD", "3.0"))

# Models and Integrations
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.1")
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "")

# Active mode environment
import sys

MODE = os.getenv("MODE")

def get_active_database():
    if MODE == "demo":
        return "storage/events_demo.db"
    elif MODE == "organization":
        return "storage/events_org.db"
    
    if "unittest" in sys.modules:
        raw_db_path = os.getenv("SQLITE_DB")
        if raw_db_path:
            return raw_db_path
        return "storage/test_events.db"
        
    raise RuntimeError(f"Invalid MODE. Expected 'demo' or 'organization'. Got: {MODE}")

# SQLite Local Database Configuration
raw_db_path = get_active_database()
if not os.path.isabs(raw_db_path):
    base_dir = os.path.dirname(os.path.abspath(__file__))
    SQLITE_DB = os.path.abspath(os.path.join(base_dir, raw_db_path))
else:
    SQLITE_DB = raw_db_path

# Agent control
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
