import requests
import json
import os
from datetime import datetime

def send_discord_webhook(webhook_url, message, embed_data=None):
    """
    Sends a rich alert to the designated Discord Webhook URL.
    """
    if not webhook_url:
        print("[Discord Alert] No Webhook URL supplied. Alert logged to console:")
        print(f"[Alert Text]: {message}")
        return False
    
    payload = {
        "content": message
    }
    
    if embed_data:
        payload["embeds"] = [embed_data]
        
    try:
        response = requests.post(
            webhook_url,
            headers={"Content-Type": "application/json"},
            data=json.dumps(payload),
            timeout=5
        )
        if response.status_code == 204:
            print("[Discord Alert] Alert successfully sent.")
            return True
        else:
            print(f"[Discord Alert] Failed to trigger alert, status code: {response.status_code}")
            return False
    except Exception as e:
        print(f"[Discord Alert] Exception throwing Discord alert: {e}")
        return False

def mask_pii(text, val_type=None):
    if not text:
        return ""
    import re
    
    if val_type == "username":
        if len(text) <= 2:
            return "*" * len(text) if len(text) > 0 else ""
        return text[0] + "*" * (len(text) - 2) + text[-1]

    # Mask email patterns
    def replace_email(match):
        email_user = match.group(1)
        email_domain = match.group(2)
        email_ext = match.group(3)
        if len(email_user) <= 2:
            return f"{email_user[0]}***@{email_domain[0]}***.{email_ext}"
        return f"{email_user[0]}***{email_user[-1]}@{email_domain[0]}***.{email_ext}"
        
    masked = re.sub(r"([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9_\-\.]+)\.([a-zA-Z]{2,5})", replace_email, text)
    
    # Mask IPv4 IP patterns
    def replace_ip(match):
        parts = match.group(0).split(".")
        return f"{parts[0]}.{parts[1]}.*.*"
        
    masked = re.sub(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", replace_ip, masked)
    
    return masked

def trigger_anomaly_discord_alert(webhook_url, anomaly_id, z_score, order_count, mean, std, db_path=None):
    """
    Formulates an enriched, structured visual Embed notification for the Discord channel.
    """
    import sqlite3
    
    severity = "HIGH"
    hybrid_score = 0.0
    possible_threat = "Pending Classification"
    threat_confidence = 0.0
    recommendation = "Pending analysis"
    gemini_summary = ""
    ai_diagnosis = ""
    diagnosis = ""
    
    # Query database to enrich the alert with latest insights
    try:
        from storage.db import get_absolute_db_path, get_db_connection
        abs_db_path = get_absolute_db_path(db_path)
        conn = get_db_connection(abs_db_path)
        cursor = conn.cursor()
        
        # Get data from anomalies
        cursor.execute(
            "SELECT severity, hybrid_score, possible_threat, threat_confidence, diagnosis, z_score, event_count, window_mean, window_std FROM anomalies WHERE id = ?",
            (anomaly_id,)
        )
        row = cursor.fetchone()
        if row:
            db_severity, db_hybrid_score, db_possible_threat, db_threat_confidence, db_diagnosis, db_z, db_count, db_mean, db_std = row
            if db_severity: severity = db_severity
            if db_hybrid_score is not None: hybrid_score = db_hybrid_score
            if db_possible_threat: possible_threat = db_possible_threat
            if db_threat_confidence is not None: threat_confidence = db_threat_confidence
            if db_diagnosis: diagnosis = db_diagnosis
            if db_z is not None: z_score = db_z
            if db_count is not None: order_count = db_count
            if db_mean is not None: mean = db_mean
            if db_std is not None: std = db_std
            
        # Get data from incidents
        cursor.execute(
            "SELECT recommendation, gemini_summary, ai_diagnosis, severity, possible_threat, threat_confidence FROM incidents WHERE anomaly_id = ?",
            (anomaly_id,)
        )
        row_inc = cursor.fetchone()
        if row_inc:
            db_rec, db_gemini, db_ai_diag, db_inc_severity, db_inc_possible_threat, db_inc_threat_confidence = row_inc
            if db_rec: recommendation = db_rec
            if db_gemini: gemini_summary = db_gemini
            if db_ai_diag: ai_diagnosis = db_ai_diag
            if db_inc_severity: severity = db_inc_severity
            if db_inc_possible_threat: possible_threat = db_inc_possible_threat
            if db_inc_threat_confidence is not None: threat_confidence = db_inc_threat_confidence
    except Exception as e:
        print(f"[Discord Alert Error] Failed to fetch threat insights for alert: {e}")
        
    possible_threat = mask_pii(possible_threat)
    recommendation = mask_pii(recommendation)
    gemini_summary = mask_pii(gemini_summary)
        
    time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    
    fields = [
        {"name": "Anomaly ID", "value": f"#{anomaly_id}", "inline": True},
        {"name": "Severity", "value": f"**{severity}**", "inline": True},
        {"name": "Current Z-Score", "value": f"**{z_score:.2f}**", "inline": True},
        {"name": "Hybrid Score", "value": f"**{hybrid_score:.2f}**", "inline": True},
        {"name": "Possible Threat", "value": f"{possible_threat}", "inline": True},
        {"name": "Threat Confidence", "value": f"{threat_confidence:.1f}%", "inline": True},
        {"name": "Events in Window", "value": f"{order_count} orders", "inline": True},
        {"name": "Baseline Mean", "value": f"{mean:.2f} orders/sec", "inline": True},
        {"name": "Baseline Std Dev", "value": f"{std:.2f}", "inline": True},
        {"name": "Timestamp", "value": time_str, "inline": False},
        {"name": "Recommendation", "value": f"{recommendation or 'N/A'}", "inline": False}
    ]
    
    if gemini_summary and gemini_summary.strip():
        fields.append({"name": "Gemini Summary", "value": gemini_summary, "inline": False})
        
    embed = {
        "title": "🚨 INCIDENT ALERT",
        "color": 15158332, # Vibrant Red
        "fields": fields,
        "description": "The system order rate has breached the Z-Score threshold. The Aegis ReAct AI Agent has been spawned to run real-time mitigation.",
        "footer": {
            "text": "Aegis Streaming Control Loop"
        }
    }
    
    # Format the required Discord payload structure explicitly in the message text content
    msg_lines = [
        "🚨 INCIDENT ALERT",
        f"Severity: {severity}",
        f"Hybrid Score: {hybrid_score:.2f}",
        f"Possible Threat: {possible_threat}",
        f"Threat Confidence: {threat_confidence:.1f}%",
        f"Recommendation: {recommendation or 'N/A'}"
    ]
    if gemini_summary and gemini_summary.strip():
        msg_lines.append(f"Gemini Summary: {gemini_summary}")
        
    msg_content = "\n\n".join(msg_lines)
    return send_discord_webhook(webhook_url, msg_content, embed)
