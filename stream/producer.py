import random
import time
import os
import sys
import json
import threading
from datetime import datetime

# Insert parent dir to import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from storage.db import insert_event, init_db
from config import EVENT_INTERVAL, SQLITE_DB

# Core running flag
_running = True

def generate_order_event():
    """
    Creates a simulated transaction event record.
    """
    order_id = f"ORD{random.randint(100000, 999999)}"
    source = random.choice(["web", "mobile", "api", "mobile", "web"]) # web & mobile are primary
    return {
        "event": "order_placed",
        "order_id": order_id,
        "timestamp": time.time(),
        "source": source
    }

def load_sample_data(sample_file):
    """
    Loads events from a JSON sample file (anomaly_sample.json, mixed_sample.json, normal_sample.json).
    Replaces static timestamps with current time offsets for live replay.
    """
    sample_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sample_data")
    file_path = os.path.join(sample_dir, sample_file)
    if not os.path.exists(file_path):
        print(f"[Producer] Sample file not found: {file_path}")
        return []
    try:
        with open(file_path, "r") as f:
            events = json.load(f)
        print(f"[Producer] Loaded {len(events)} events from {sample_file}")
        return events
    except Exception as e:
        print(f"[Producer] Error loading sample file: {e}")
        return []

def replay_sample_data(events, db_path=SQLITE_DB, speed_multiplier=1.0, queue=None):
    """
    Replays sample events into the database with real-time timestamps.
    Handles mixed datasets containing both anomaly spikes and normal traffic.
    """
    if not events:
        return
    base_interval = EVENT_INTERVAL / speed_multiplier
    t_start = time.time()
    original_base = events[0].get("timestamp", t_start)
    
    for i, evt in enumerate(events):
        if not _running:
            break
        # Remap original timestamps to current time
        time_offset = evt.get("timestamp", original_base) - original_base
        new_timestamp = t_start + time_offset
        
        insert_event(
            evt.get("event", "order_placed"),
            evt.get("order_id", f"ORD_REPLAY_{i}"),
            new_timestamp,
            evt.get("source", "web"),
            db_path=db_path
        )
        if queue is not None:
            queue.put(evt)
        
        # Small delay between events for realistic streaming
        time.sleep(base_interval)
    
    print(f"[Producer] Completed replay of {len(events)} events from sample data.")

def producer_worker(queue=None, db_path=SQLITE_DB, interval=EVENT_INTERVAL, sample_file=None):
    """
    Runs continuously, generating standard steady state events and occasional heavy traffic surges.
    If sample_file is provided, replays that dataset first before switching to live generation.
    """
    global _running
    print(f"[Producer] Initiated background order stream using database {db_path}...")
    init_db(db_path)
    
    # Load all sample files for continuous enterprise loop
    normal_events = load_sample_data("normal_sample.json")
    bruteforce_events = load_sample_data("bruteforce_sample.json")
    ddos_events = load_sample_data("ddos_sample.json")
    exfil_events = load_sample_data("exfiltration_sample.json")
    insider_events = load_sample_data("insider_sample.json")
    service_failure_events = load_sample_data("service_failure_sample.json")
    
    # Fallback lists in case sample files are missing or empty
    if not normal_events:
        normal_events = [
            {"event": "user_auth", "order_id": "AUTH_SUCCESS_01", "source": "vpn"},
            {"event": "firewall_accept", "order_id": "FW_ACCEPT_01", "source": "gateway"},
            {"event": "api_request", "order_id": "API_GET_01", "source": "api"},
            {"event": "order_placed", "order_id": "ORD309482", "source": "web"}
        ]
    if not bruteforce_events:
        bruteforce_events = [{"event": "failed_login", "order_id": f"FAIL_AUTH_{i}", "source": "web"} for i in range(55)]
    if not ddos_events:
        ddos_events = [{"event": "order_placed", "order_id": f"ORD_DDOS_{i}", "source": "api"} for i in range(120)]
    if not exfil_events:
        exfil_events = [{"event": "data_transfer", "order_id": f"EXFIL_DATA_{i}", "source": "api"} for i in range(20)]
    if not insider_events:
        insider_events = [{"event": "privileged_action", "order_id": f"ADMIN_CONFIG_{i}", "source": "console"} for i in range(15)]
    if not service_failure_events:
        service_failure_events = [{"event": "heartbeat_miss", "order_id": f"SERVICE_DROP_{i}", "source": "internal"} for i in range(15)]
        
    current_phase = 0
    phase_ticks_elapsed = 0
    normal_event_idx = 0
    
    # Replay sample data if specified (supports mixed anomaly + normal datasets)
    if sample_file:
        events = load_sample_data(sample_file)
        if events:
            replay_sample_data(events, db_path=db_path, queue=queue)
    
    while _running:
        is_incident_phase = current_phase % 2 == 1
        duration_ms = 10000 if is_incident_phase else 40000
        max_ticks = int(duration_ms / (interval * 1000))
        if max_ticks < 1:
            max_ticks = 1
            
        if phase_ticks_elapsed >= max_ticks:
            current_phase = (current_phase + 1) % 11
            phase_ticks_elapsed = 0
            print(f"[Producer] Transitioning to Phase {current_phase} (isIncident: {current_phase % 2 == 1})")
            
        # Start of incident phase - inject burst!
        if current_phase % 2 == 1 and phase_ticks_elapsed == 0:
            burst_events = []
            if current_phase == 1:
                burst_events = bruteforce_events
            elif current_phase == 3:
                burst_events = ddos_events
            elif current_phase == 5:
                burst_events = exfil_events
            elif current_phase == 7:
                burst_events = insider_events
            elif current_phase == 9:
                burst_events = service_failure_events
                
            print(f"[Producer] Phase {current_phase}: Injecting burst of {len(burst_events)} events...")
            for evt in burst_events:
                order_id = evt.get("order_id") or f"ORD{random.randint(100000, 999999)}"
                insert_event(
                    evt.get("event", "order_placed"),
                    order_id,
                    time.time(),
                    evt.get("source", "web"),
                    db_path=db_path
                )
                if queue is not None:
                    queue.put({
                        "event": evt.get("event", "order_placed"),
                        "order_id": order_id,
                        "timestamp": time.time(),
                        "source": evt.get("source", "web")
                    })
                    
        # Always inject normal baseline event
        normal_evt = normal_events[normal_event_idx % len(normal_events)]
        normal_event_idx += 1
        order_id = f"ORD{random.randint(100000, 999999)}"
        evt_to_send = {
            "event": normal_evt.get("event", "order_placed"),
            "order_id": order_id,
            "timestamp": time.time(),
            "source": normal_evt.get("source", "web")
        }
        insert_event(
            evt_to_send["event"],
            evt_to_send["order_id"],
            evt_to_send["timestamp"],
            evt_to_send["source"],
            db_path=db_path
        )
        if queue is not None:
            queue.put(evt_to_send)
            
        phase_ticks_elapsed += 1
        time.sleep(interval)

def stop_producer():
    global _running
    _running = False

if __name__ == "__main__":
    # If run standalone, execute on local thread
    import queue as py_queue
    import argparse
    
    parser = argparse.ArgumentParser(description="Aegis Event Stream Producer")
    parser.add_argument("--sample", type=str, default=None,
                        help="Sample data file to replay (anomaly_sample.json, mixed_sample.json, normal_sample.json)")
    parser.add_argument("--db", type=str, default="storage/events.db",
                        help="Path to SQLite database")
    args = parser.parse_args()
    
    q = py_queue.Queue()
    try:
        producer_worker(queue=q, db_path=args.db, sample_file=args.sample)
    except KeyboardInterrupt:
        print("\n[Producer] Terminating...")
        stop_producer()
