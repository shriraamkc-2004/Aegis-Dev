# Sensitive field encryption protects secrets and credentials only.
# PII masking is applied during presentation and external exposure only.
# Operational SOC telemetry remains unencrypted and unmasked internally to preserve detection accuracy and forensic integrity.

import sqlite3
import os
import threading
from datetime import datetime

# Thread-local storage for database connections to avoid concurrency conflicts
_local = threading.local()

def get_absolute_db_path(db_path=None):
    if db_path is None:
        from config import SQLITE_DB
        return SQLITE_DB
    if not os.path.isabs(db_path):
        # Resolve relative to the project root directory (parent of storage/db.py)
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        return os.path.abspath(os.path.join(base_dir, db_path))
    return db_path

def get_db_connection(db_path=None):
    db_path = get_absolute_db_path(db_path)
    if not hasattr(_local, "conn") or _local.conn is None:
        # Ensure the directory exists
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        _local.conn = sqlite3.connect(db_path, timeout=30.0)
        _local.conn.execute("PRAGMA journal_mode=WAL;")
        _local.conn.execute("PRAGMA synchronous=NORMAL;")
        _local.conn.execute("PRAGMA busy_timeout=30000;")
    return _local.conn

def close_db_connection():
    if hasattr(_local, "conn") and _local.conn is not None:
        try:
            _local.conn.close()
        except Exception:
            pass
        _local.conn = None


def init_db(db_path=None):
    db_path = get_absolute_db_path(db_path)
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=30.0)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA busy_timeout=30000;")
    cursor = conn.cursor()
    
    # Create events table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_type TEXT,
        order_id TEXT,
        timestamp REAL,
        source TEXT,
        organization_id INTEGER DEFAULT 1,
        formatted_time TEXT GENERATED ALWAYS AS (datetime(timestamp, 'unixepoch'))
    )
    """)
    
    # Create anomalies table (synced with TypeScript schema)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS anomalies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp REAL,
        z_score REAL,
        window_mean REAL,
        window_std REAL,
        event_count INTEGER,
        status TEXT DEFAULT 'Pending Mitigation',
        diagnosis TEXT DEFAULT 'No analysis yet.',
        severity TEXT DEFAULT 'MEDIUM',
        iforest_score REAL DEFAULT 0.0,
        ewma_score REAL DEFAULT 0.0,
        hybrid_score REAL DEFAULT 0.0,
        detection_method TEXT DEFAULT 'ZSCORE',
        source_entropy REAL DEFAULT 0.0,
        burst_ratio REAL DEFAULT 0.0,
        organization_id INTEGER DEFAULT 1,
        possible_threat TEXT DEFAULT '',
        threat_confidence REAL DEFAULT 0.0,
        recommendation TEXT DEFAULT '',
        formatted_time TEXT GENERATED ALWAYS AS (datetime(timestamp, 'unixepoch'))
    )
    """)
    
    # Run migrations/alter table for anomalies to ensure backward compatibility
    columns_to_add = [
        ("severity", "TEXT DEFAULT 'MEDIUM'"),
        ("iforest_score", "REAL DEFAULT 0.0"),
        ("ewma_score", "REAL DEFAULT 0.0"),
        ("hybrid_score", "REAL DEFAULT 0.0"),
        ("detection_method", "TEXT DEFAULT 'ZSCORE'"),
        ("source_entropy", "REAL DEFAULT 0.0"),
        ("burst_ratio", "REAL DEFAULT 0.0"),
        ("organization_id", "INTEGER DEFAULT 1"),
        ("possible_threat", "TEXT DEFAULT ''"),
        ("threat_confidence", "REAL DEFAULT 0.0"),
        ("recommendation", "TEXT DEFAULT ''")
    ]
    for col_name, col_def in columns_to_add:
        try:
            cursor.execute(f"ALTER TABLE anomalies ADD COLUMN {col_name} {col_def}")
        except sqlite3.OperationalError:
            pass  # Column already exists
            
    # Create incidents table for full incident management lifecycle
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS incidents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        anomaly_id INTEGER DEFAULT NULL,
        title TEXT NOT NULL DEFAULT '',
        description TEXT DEFAULT '',
        status TEXT DEFAULT 'OPEN',
        severity TEXT DEFAULT 'MEDIUM',
        detection_time REAL,
        root_cause TEXT DEFAULT '',
        ai_diagnosis TEXT DEFAULT '',
        analyst_notes TEXT DEFAULT '',
        resolution TEXT DEFAULT '',
        recommended_action TEXT DEFAULT '',
        assigned_to INTEGER DEFAULT NULL,
        created_by INTEGER DEFAULT NULL,
        organization_id INTEGER DEFAULT 1,
        possible_threat TEXT DEFAULT '',
        threat_confidence REAL DEFAULT 0.0,
        recommendation TEXT DEFAULT '',
        gemini_summary TEXT DEFAULT '',
        created_at REAL DEFAULT (strftime('%s','now')),
        updated_at REAL DEFAULT (strftime('%s','now')),
        FOREIGN KEY(anomaly_id) REFERENCES anomalies(id)
    )
    """)

    # Run migrations/alter table for incidents to ensure backward compatibility
    inc_columns_to_add = [
        ("possible_threat", "TEXT DEFAULT ''"),
        ("threat_confidence", "REAL DEFAULT 0.0"),
        ("recommendation", "TEXT DEFAULT ''"),
        ("gemini_summary", "TEXT DEFAULT ''")
    ]
    for col_name, col_def in inc_columns_to_add:
        try:
            cursor.execute(f"ALTER TABLE incidents ADD COLUMN {col_name} {col_def}")
        except sqlite3.OperationalError:
            pass  # Column already exists
            
    # Create agent_logs table for tracking thoughts, actions, observation steps
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS agent_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        anomaly_id INTEGER,
        timestamp REAL,
        step INTEGER,
        type TEXT, -- 'Thought', 'Action', 'Observation', 'Final Response'
        content TEXT,
        formatted_time TEXT GENERATED ALWAYS AS (datetime(timestamp, 'unixepoch')),
        FOREIGN KEY(anomaly_id) REFERENCES anomalies(id)
    )
    """)

    # Conditionally create enterprise sandbox tables only in Organization Mode
    from config import MODE
    if MODE == "organization":
        tables = ["authentication_logs", "firewall_logs", "vpn_logs", "network_events", "application_logs"]
        for tbl in tables:
            cursor.execute(f"""
            CREATE TABLE IF NOT EXISTS "{tbl}" (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_time REAL NOT NULL,
                event_type TEXT NOT NULL,
                event_source TEXT,
                user_name TEXT,
                source_ip TEXT,
                department TEXT,
                status TEXT,
                details TEXT,
                reference_id TEXT,
                amount REAL DEFAULT 0,
                endpoint TEXT,
                http_method TEXT,
                severity_level TEXT DEFAULT 'LOW',
                table_name TEXT DEFAULT '{tbl}'
            )
            """)
    
    conn.commit()
    conn.close()

def insert_event(event_type, order_id, timestamp, source, db_path=None):
    db_path = get_absolute_db_path(db_path)
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO events (event_type, order_id, timestamp, source) VALUES (?, ?, ?, ?)",
        (event_type, order_id, timestamp, source)
    )
    conn.commit()
    return cursor.lastrowid

def insert_anomaly(timestamp, z_score, window_mean, window_std, event_count,
                   severity="MEDIUM", iforest_score=0.0, ewma_score=0.0,
                   hybrid_score=0.0, detection_method="ZSCORE",
                   source_entropy=0.0, burst_ratio=0.0, organization_id=1,
                   possible_threat="", threat_confidence=0.0, recommendation="", db_path=None):
    db_path = get_absolute_db_path(db_path)
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute(
        """INSERT INTO anomalies 
           (timestamp, z_score, window_mean, window_std, event_count, severity, 
            iforest_score, ewma_score, hybrid_score, detection_method, source_entropy, burst_ratio, 
            organization_id, possible_threat, threat_confidence, recommendation) 
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (timestamp, z_score, window_mean, window_std, event_count, severity,
         iforest_score, ewma_score, hybrid_score, detection_method, source_entropy, burst_ratio, 
         organization_id, possible_threat, threat_confidence, recommendation)
    )
    conn.commit()
    return cursor.lastrowid

def update_anomaly_status(anomaly_id, status, diagnosis, db_path=None):
    db_path = get_absolute_db_path(db_path)
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE anomalies SET status = ?, diagnosis = ? WHERE id = ?",
        (status, diagnosis, anomaly_id)
    )
    conn.commit()

def insert_agent_log(anomaly_id, step, log_type, content, db_path=None):
    db_path = get_absolute_db_path(db_path)
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO agent_logs (anomaly_id, timestamp, step, type, content) VALUES (?, ?, ?, ?, ?)",
        (anomaly_id, datetime.now().timestamp(), step, log_type, content)
    )
    conn.commit()
    return cursor.lastrowid

def insert_incident(anomaly_id, title, description, severity, 
                    possible_threat="", threat_confidence=0.0, recommendation="", gemini_summary="", db_path=None):
    """
    Creates an incident record linked to an anomaly for full incident lifecycle tracking.
    """
    db_path = get_absolute_db_path(db_path)
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    now = datetime.now().timestamp()
    cursor.execute(
        """INSERT INTO incidents
           (anomaly_id, title, description, severity, detection_time, status, root_cause, ai_diagnosis, 
            recommended_action, organization_id, possible_threat, threat_confidence, recommendation, gemini_summary)
           VALUES (?, ?, ?, ?, ?, 'OPEN', ?, ?, ?, 1, ?, ?, ?, ?)""",
        (anomaly_id, title, description, severity, now,
         f"Traffic spike detected at anomaly #{anomaly_id}.",
         "Pending AI agent analysis.",
         f"Investigate anomaly #{anomaly_id} traffic sources and verify if malicious.",
         possible_threat, threat_confidence, recommendation, gemini_summary)
    )
    conn.commit()
    return cursor.lastrowid

def update_incident_status(anomaly_id, status, root_cause, ai_diagnosis, resolution, recommended_action, db_path=None):
    """
    Updates the incident linked to an anomaly with resolution details.
    """
    db_path = get_absolute_db_path(db_path)
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    now = datetime.now().timestamp()
    cursor.execute(
        """UPDATE incidents
           SET status = ?, root_cause = ?, ai_diagnosis = ?, resolution = ?, recommended_action = ?, updated_at = ?
           WHERE anomaly_id = ? AND status = 'OPEN'""",
        (status, root_cause, ai_diagnosis, resolution, recommended_action, now, anomaly_id)
    )
    conn.commit()

def update_incident_gemini_summary(anomaly_id, gemini_summary, db_path=None):
    """
    Updates the gemini_summary for an incident.
    """
    db_path = get_absolute_db_path(db_path)
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE incidents SET gemini_summary = ? WHERE anomaly_id = ?",
        (gemini_summary, anomaly_id)
    )
    conn.commit()
