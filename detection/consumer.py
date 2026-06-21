# Sensitive field encryption protects secrets and credentials only.
# PII masking is applied during presentation and external exposure only.
# Operational SOC telemetry remains unencrypted and unmasked internally to preserve detection accuracy and forensic integrity.

import time
import os
import sys
import math
import subprocess
from datetime import datetime

# Insert parent dir to import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from storage.db import insert_anomaly, insert_incident, get_db_connection
from alerts.discord_alert import trigger_anomaly_discord_alert
from config import WINDOW_SIZE, Z_SCORE_THRESHOLD, SQLITE_DB, DISCORD_WEBHOOK_URL

def calculate_stats(window_counts):
    """
    Computes mathematical mean and sample standard deviation of historical bins.
    Does not require numpy for high compatibility.
    """
    if not window_counts:
        return 0.0, 0.0
        
    n = len(window_counts)
    mean = sum(window_counts) / n
    if n <= 1:
        return mean, 0.0
        
    variance = sum((x - mean) ** 2 for x in window_counts) / (n - 1)
    std_dev = math.sqrt(variance)
    return mean, std_dev

def running_detector_loop(db_path=SQLITE_DB, window_size=WINDOW_SIZE, threshold=Z_SCORE_THRESHOLD, webhook_url=DISCORD_WEBHOOK_URL):
    """
    Continuously queries recent events from SQLite, aggregates them in 1-second bins,
    maintains a sliding window of observations, and triggers automated AI containment workflows on surges.
    """
    print(f"[Detector] Starting Sliding Window Z-Score Consumer on DB: {db_path}...")
    print(f"[Detector] Configuration: Window={window_size}s, Threshold={threshold}")
    
    # Track the last executed alert timestamp to avoid continuous multi-firing
    last_alert_time = 0.0
    cooldown_seconds = 10.0  # 10s quiet period
    
    while True:
        try:
            curr_time = time.time()
            conn = get_db_connection(db_path)
            cursor = conn.cursor()
            
            # Query count of events grouped by 1-second intervals for the last (window_size + 1) seconds
            start_time = curr_time - window_size - 2
            cursor.execute(
                "SELECT CAST(timestamp as INTEGER) as sec, COUNT(*) FROM events WHERE timestamp >= ? GROUP BY sec ORDER BY sec DESC",
                (start_time,)
            )
            rows = cursor.fetchall()
            
            # Map recent seconds to counts
            counts_map = {row[0]: row[1] for row in rows}
            
            # Current second integer
            current_sec = int(curr_time)
            current_count = counts_map.get(current_sec, 0)
            
            # History counts (excluding the current second to avoid self-influence)
            history_counts = []
            for i in range(1, window_size + 1):
                sec_check = current_sec - i
                history_counts.append(counts_map.get(sec_check, 0))
                
            mean, std_dev = calculate_stats(history_counts)
            
            if std_dev > 0:
                z_score = (current_count - mean) / std_dev
            else:
                z_score = 0.0
                
            # Log debug metrics occasionally
            if current_sec % 5 == 0:
                print(f"[Detector Metrics] Time: {datetime.now().strftime('%H:%M:%S')} | Current Rate: {current_count} orders/sec | Window Mean: {mean:.2f} | Std Dev: {std_dev:.2f} | Z-Score: {z_score:.2f}")
                
            # If Z-score exceeds threshold and current rate is above static minimum (to avoid alert on tiny variance)
            if z_score > threshold and current_count > 5:
                if curr_time - last_alert_time > cooldown_seconds:
                    last_alert_time = curr_time
                    print(f"\n[Detector] 🚨 ANOMALY BREACH! Z-Score: {z_score:.2f} (Threshold: {threshold})")
                    print(f"[Detector] Event Rate: {current_count} orders/s | Baseline Mean: {mean:.2f} | Std Dev: {std_dev:.2f}")
                    
                    # 1. Run local threat classification
                    from detections.threat_classifier import ThreatClassifier
                    classifier = ThreatClassifier(db_path=db_path)
                    possible_threat, threat_confidence, recommendation = classifier.classify(curr_time, current_count, z_score)
                    
                    # 2. Store Anomaly record inside local SQLite
                    anomaly_id = insert_anomaly(
                        curr_time, z_score, mean, std_dev, current_count,
                        possible_threat=possible_threat, threat_confidence=threat_confidence,
                        recommendation=recommendation, db_path=db_path
                    )
                    print(f"[Detector] Registered Anomaly #{anomaly_id} inside Local Database. Threat: {possible_threat} ({threat_confidence:.1f}%)")
                    
                    # 2b. Create linked Incident record for full lifecycle tracking
                    severity = "CRITICAL" if z_score > threshold * 2 else "HIGH" if z_score > threshold * 1.5 else "MEDIUM"
                    title = f"[ZSCORE] {severity} Severity Anomaly Breach #{anomaly_id}"
                    desc = (f"Z-Score detection triggered at {current_count} events/sec. "
                            f"Z-Score={z_score:.2f} (threshold: {threshold}), "
                            f"Window: mean={mean:.2f}, std={std_dev:.2f}.")
                    incident_id = insert_incident(
                        anomaly_id, title, desc, severity,
                        possible_threat=possible_threat, threat_confidence=threat_confidence,
                        recommendation=recommendation, db_path=db_path
                    )
                    print(f"[Detector] Created Incident #{incident_id} for Anomaly #{anomaly_id}.")
                    
                    # 2. Dispatch the rich Discord Webhook alert
                    try:
                        trigger_anomaly_discord_alert(webhook_url, anomaly_id, z_score, current_count, mean, std_dev)
                    except Exception as discord_err:
                        print(f"[Detector] Failed pushing Discord notice: {discord_err}")
                        
                    # 3. Spawn autonomous AI mitigation agent process
                    print(f"[Detector] Spawning autonomous ReAct loop subprocess for Anomaly #{anomaly_id}...")
                    subprocess.Popen([sys.executable, "ai/agent_loop.py", str(anomaly_id)])
                    
            time.sleep(1.0)
        except Exception as e:
            print(f"[Detector Error] Error processed in sliding window: {str(e)}")
            time.sleep(2.0)

if __name__ == "__main__":
    try:
        running_detector_loop()
    except KeyboardInterrupt:
        print("\n[Detector] Terminated.")
