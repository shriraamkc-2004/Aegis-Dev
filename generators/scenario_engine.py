# Sensitive field encryption protects secrets and credentials only.
# PII masking is applied during presentation and external exposure only.
# Operational SOC telemetry remains unencrypted and unmasked internally to preserve detection accuracy and forensic integrity.

import sqlite3
import json
import time
import os
import random
import sys

# Configure stdout buffering and encoding to ensure logs print immediately and do not crash on Windows
try:
    sys.stdout.reconfigure(line_buffering=True, encoding="utf-8")
except Exception:
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except Exception:
        pass

# Resolve directories
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(base_dir)

# Initialize database using Aegis storage config and helper
from storage.db import init_db, get_absolute_db_path

def main():
    print("[Scenario Engine] Starting engine...")
    
    # 1. Load sequence dataset
    sequence_path = os.path.join(base_dir, "datasets", "enterprise_demo_sequence.json")
    if not os.path.exists(sequence_path):
        print(f"[Scenario Engine] ERROR: Dataset sequence not found at {sequence_path}")
        sys.exit(1)
        
    try:
        with open(sequence_path, "r") as f:
            sequence = json.load(f)
        print(f"[Scenario Engine] Loaded {len(sequence)} phases from {sequence_path}")
    except Exception as e:
        print(f"[Scenario Engine] ERROR: Failed loading dataset sequence JSON: {e}")
        sys.exit(1)
        
    # 2. Resolve database path (forced events_demo.db via MODE=demo)
    os.environ["MODE"] = "demo" # Explicit safety guarantee
    db_path = get_absolute_db_path()
    print(f"[Scenario Engine] Using isolated database path: {db_path}")
    
    # Ensure database folder exists and initialize schema
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    init_db(db_path)
    print("[Scenario Engine] Database schema verified and ready.")
    
    # 3. Infinite workday simulation loop
    loop_count = 1
    while True:
        print(f"\n[Scenario Engine] Starting workday simulation cycle #{loop_count}...")
        for phase_block in sequence:
            phase = phase_block.get("phase", "normal")
            events = phase_block.get("events", [])
            
            is_attack = phase in ["bruteforce", "ddos", "exfiltration", "insider", "service_failure"]
            duration = 10.0 if is_attack else 40.0
            
            print(f"[Scenario Engine] Phase: '{phase}' | Duration: {duration}s | Expected Events: {len(events)}")
            
            phase_start = time.time()
            sent_indices = set()
            
            # Loop inside the phase duration
            while True:
                elapsed = time.time() - phase_start
                if elapsed >= duration:
                    break
                    
                # Collect events whose offset has passed
                batch_inserts = []
                for idx, evt in enumerate(events):
                    if idx in sent_indices:
                        continue
                    offset = evt.get("timestamp_offset", 0.0)
                    if elapsed >= offset:
                        payload = evt.get("event_payload", {})
                        event_type = payload.get("event_type", "order_placed")
                        source = payload.get("source", "web")
                        order_id = payload.get("order_id", f"ORD{random.randint(100000, 999999)}")
                        
                        batch_inserts.append((event_type, order_id, time.time(), source))
                        sent_indices.add(idx)
                        
                # Perform batch inserts for high performance and integrity
                if batch_inserts:
                    try:
                        conn = sqlite3.connect(db_path, timeout=30.0)
                        conn.execute("PRAGMA journal_mode=WAL;")
                        cursor = conn.cursor()
                        cursor.executemany(
                            "INSERT INTO events (event_type, order_id, timestamp, source) VALUES (?, ?, ?, ?)",
                            batch_inserts
                        )
                        conn.commit()
                        conn.close()
                    except Exception as ex:
                        print(f"[Scenario Engine] Database insert error: {ex}")
                        
                # Sleep a short tick interval to minimize CPU load
                time.sleep(0.05)
                
        loop_count += 1

if __name__ == "__main__":
    main()
