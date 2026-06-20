# Sensitive field encryption protects secrets and credentials only.
# PII masking is applied during presentation and external exposure only.
# Operational SOC telemetry remains unencrypted and unmasked internally to preserve detection accuracy and forensic integrity.

import sqlite3
import os

class ThreatClassifier:
    """
    Applies rule-based threat insights and confidence scoring to detected anomalies.
    Returns: (possible_threat, threat_confidence, recommendation)
    """
    def __init__(self, db_path):
        from storage.db import get_absolute_db_path
        self.db_path = get_absolute_db_path(db_path)

    def classify(self, timestamp, event_count, z_score):
        failed_logins = 0
        large_transfers = 0
        privileged_actions = 0
        service_drops = 0

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Look at events in the last 60 seconds
            start_time = timestamp - 60

            # Get list of existing tables
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [r[0] for r in cursor.fetchall()]

            # Query standard events table
            cursor.execute(
                "SELECT event_type, source, order_id FROM events WHERE timestamp >= ?",
                (start_time,)
            )
            recent_events = cursor.fetchall()
            
            for event_type, source, order_id in recent_events:
                et_lower = str(event_type or "").lower()
                src_lower = str(source or "").lower()
                ord_lower = str(order_id or "").lower()
                
                # Check for Brute force indicators
                if any(x in et_lower or x in src_lower or x in ord_lower for x in ["fail", "auth", "login", "brute"]):
                    if "fail" in et_lower or "fail" in ord_lower or "brute" in et_lower:
                        failed_logins += 1
                
                # Check for Exfiltration indicators
                if any(x in et_lower or x in src_lower or x in ord_lower for x in ["exfil", "transfer", "outbound", "export", "download"]):
                    large_transfers += 1
                    
                # Check for Insider threat indicators
                if any(x in et_lower or x in src_lower or x in ord_lower for x in ["privileged", "config", "admin", "policy", "sensitive", "insider"]):
                    privileged_actions += 1
                    
                # Check for Service Failure indicators
                if any(x in et_lower or x in src_lower or x in ord_lower for x in ["heartbeat", "drop", "miss", "failure", "inactive", "service_fail"]):
                    service_drops += 1

            # Check sandbox tables if they exist in Org mode
            if "authentication_logs" in tables:
                try:
                    cursor.execute("SELECT COUNT(*) FROM authentication_logs WHERE event_time >= ? AND status = 'failed'", (start_time,))
                    failed_logins += cursor.fetchone()[0]
                except Exception:
                    pass
            if "vpn_logs" in tables:
                try:
                    cursor.execute("SELECT COUNT(*) FROM vpn_logs WHERE event_time >= ? AND status = 'failed'", (start_time,))
                    failed_logins += cursor.fetchone()[0]
                except Exception:
                    pass
            if "network_events" in tables:
                try:
                    cursor.execute("SELECT COUNT(*) FROM network_events WHERE event_time >= ? AND (event_type = 'data_transfer' OR amount > 1000000)", (start_time,))
                    large_transfers += cursor.fetchone()[0]
                except Exception:
                    pass
            if "application_logs" in tables:
                try:
                    cursor.execute("SELECT COUNT(*) FROM application_logs WHERE event_time >= ? AND (severity_level = 'CRITICAL' OR user_name IN ('admin', 'superadmin') OR event_type = 'privileged_action')", (start_time,))
                    privileged_actions += cursor.fetchone()[0]
                except Exception:
                    pass

            conn.close()
        except Exception as e:
            print(f"[ThreatClassifier Error] Database check failed: {e}")

        # Classification mapping rules (checking brute force first as priority)
        if failed_logins >= 10:
            return (
                "Possible Brute Force Activity",
                82.0,
                "Review authentication logs and lock affected accounts."
            )
        elif service_drops > 0 or event_count <= 2:
            return (
                "Possible Service Failure",
                74.0,
                "Investigate infrastructure health and service availability."
            )
        elif large_transfers > 0:
            return (
                "Possible Data Exfiltration",
                71.0,
                "Review outbound traffic and investigate affected systems."
            )
        elif privileged_actions > 0:
            return (
                "Possible Insider Threat",
                69.0,
                "Audit privileged access and investigate user activity."
            )
        elif event_count >= 10 or z_score > 3.0:
            return (
                "Possible DDoS Activity",
                76.0,
                "Review network traffic and enable mitigation controls."
            )
        else:
            return (
                "Possible DDoS Activity",
                65.0,
                "Review network traffic and enable mitigation controls."
            )
