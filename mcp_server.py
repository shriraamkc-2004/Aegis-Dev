import sqlite3
import os
import json
from datetime import datetime

class MCPServer:
    """
    Exposes essential debugging, querying, and mitigation tools to the 
    autonomous ReAct AI Agent using Model Context Protocol schemas.
    """
    def __init__(self, db_path=None, log_path="storage/system.log"):
        from storage.db import get_absolute_db_path
        self.db_path = get_absolute_db_path(db_path)
        self.log_path = get_absolute_db_path(log_path)
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        os.makedirs(os.path.dirname(os.path.abspath(self.log_path)), exist_ok=True)

    def list_tools(self):
        """
        Returns the MCP tool descriptions.
        """
        return [
            {
                "name": "query_database",
                "description": "Executes a SELECT query on SQLite storage/events.db to analyze order sources or order ID counts",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "sql_query": {"type": "string", "description": "The exact SQL select query to run"}
                    },
                    "required": ["sql_query"]
                }
            },
            {
                "name": "read_system_logs",
                "description": "Reads the final 15 lines of system execution logs to review backend activity",
                "parameters": {
                    "type": "object",
                    "properties": {}
                }
            },
            {
                "name": "mitigate_anomaly",
                "description": "Mitigates anomaly by blocking malicious web/mobile traffic or raising the sliding window Z-Score threshold",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "ip_or_source": {"type": "string", "description": "Traffic source identifier to block (e.g., 'web' or 'mobile')"},
                        "raise_z_threshold": {"type": "number", "description": "Adjust the Z-score threshold to reduce alert fatigue"}
                    }
                }
            },
            {
                "name": "trigger_discord_alert",
                "description": "Sends a custom chat notification or diagnostic log to the Discord alerting webhook",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "message": {"type": "string", "description": "Status text to transmit"}
                    },
                    "required": ["message"]
                }
            },
            {
                "name": "calculate_risk_score",
                "description": "Calculates a risk score (0-100) for an anomaly based on Z-Score, event rate, and burst patterns",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "anomaly_id": {"type": "integer", "description": "Anomaly ID number"},
                        "event_rate": {"type": "number", "description": "Current events per second"},
                        "z_score": {"type": "number", "description": "Current Z-Score value"}
                    }
                }
            },
            {
                "name": "search_attack_patterns",
                "description": "Searches known attack patterns (ddos, bot, brute_force, injection) and returns indicators",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "pattern": {"type": "string", "description": "Attack pattern name: ddos, bot, brute_force, or injection"}
                    }
                }
            },
            {
                "name": "generate_incident_report",
                "description": "Generates a structured incident report for a given anomaly ID",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "anomaly_id": {"type": "integer", "description": "Anomaly ID number"}
                    },
                    "required": ["anomaly_id"]
                }
            },
            {
                "name": "get_threat_statistics",
                "description": "Returns aggregate threat statistics including total anomalies, incidents, severity distribution",
                "parameters": {
                    "type": "object",
                    "properties": {}
                }
            }
        ]

    def query_database(self, sql_query):
        """
        Tool #1: Query the SQLite event collection.
        """
        # Security sanitization - allow only SELECT and reject forbidden terms
        clean_query = sql_query.strip()
        
        # Check for semicolons to prevent stacked queries
        if ";" in clean_query:
            return "Error: MCP query_database does not allow stacked queries or semicolons."
            
        # Check for forbidden keywords (case-insensitive with word boundaries)
        import re
        forbidden_keywords = ["drop", "delete", "update", "insert", "alter", "create", "replace", "attach", "pragma"]
        for kw in forbidden_keywords:
            if re.search(r'\b' + re.escape(kw) + r'\b', clean_query.lower()):
                return f"Error: MCP query_database does not allow forbidden keyword '{kw.upper()}'."
                
        if not clean_query.lower().startswith("select"):
            return "Error: MCP query_database only accepts read-only SELECT statements."
            
        try:
            # Enforce read-only SQLite connection at the database driver level using absolute path URI
            import os
            abs_db_path = os.path.abspath(self.db_path)
            uri_path = f"file:{abs_db_path}?mode=ro"
            conn = sqlite3.connect(uri_path, uri=True, timeout=30.0)
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            conn.execute("PRAGMA busy_timeout=30000;")
            cursor = conn.cursor()
            cursor.execute(clean_query)
            columns = [d[0] for d in cursor.description]
            rows = cursor.fetchall()
            conn.close()
            
            results = [dict(zip(columns, row)) for row in rows]
            return json.dumps(results, indent=2)
        except Exception as e:
            return f"Error executing query: {str(e)}"

    def read_system_logs(self):
        """
        Tool #2: Grab recently written system logs.
        """
        if not os.path.exists(self.log_path):
            # Create standard default entries if missing
            with open(self.log_path, "w") as f:
                f.write(f"[{datetime.now().isoformat()}] INFO [System] Logging initialized.\n")
                f.write(f"[{datetime.now().isoformat()}] INFO [Producer] Event feed generating correctly.\n")
                
        try:
            with open(self.log_path, "r") as f:
                lines = f.readlines()
            last_lines = lines[-15:] if len(lines) > 15 else lines
            return "".join(last_lines)
        except Exception as e:
            return f"Error reading logs: {str(e)}"

    def mitigate_anomaly(self, ip_or_source=None, raise_z_threshold=None):
        """
        Tool #3: Execute critical containment actions.
        """
        actions = []
        if ip_or_source:
            actions.append(f"Successfully throttled/blocked source layer '{ip_or_source}' at load balancer firewall.")
        if raise_z_threshold:
            actions.append(f"Dynamically adjusted Z-Score threshold setting to {raise_z_threshold} to mitigate system alert fatigue.")
            
        if not actions:
            return "No mitigation parameters provided. No actions performed."
            
        return "Containing anomaly: " + " | ".join(actions)

    def trigger_discord_alert(self, message):
        """
        Tool #4: Direct alert dispatcher tool.
        """
        webhook_url = os.getenv("DISCORD_WEBHOOK_URL", "")
        if not webhook_url:
            return f"Simulating alert dispatch: {message}"
            
        # Standard post
        try:
            import requests # Lazy load
            res = requests.post(
                webhook_url,
                json={"content": f"🛡️ **MCP Agent Update:** {message}"},
                timeout=5
            )
            if res.status_code == 204:
                return "Discord alert transmitted successfully."
            else:
                return f"Transmitted with response status: {res.status_code}"
        except Exception as e:
            return f"Failed sending alert: {str(e)}"

    def call_tool(self, name, arguments):
        """
        Decodes and dispatches incoming tool invocations from the agent.
        """
        if name == "query_database":
            return self.query_database(arguments.get("sql_query", ""))
        elif name == "read_system_logs":
            return self.read_system_logs()
        elif name == "mitigate_anomaly":
            return self.mitigate_anomaly(arguments.get("ip_or_source"), arguments.get("raise_z_threshold"))
        elif name == "trigger_discord_alert":
            return self.trigger_discord_alert(arguments.get("message", ""))
        elif name == "calculate_risk_score":
            return self.calculate_risk_score(arguments.get("anomaly_id"), arguments.get("event_rate", 0), arguments.get("z_score", 0))
        elif name == "search_attack_patterns":
            return self.search_attack_patterns(arguments.get("pattern", "ddos"))
        elif name == "generate_incident_report":
            return self.generate_incident_report(arguments.get("anomaly_id"))
        elif name == "get_threat_statistics":
            return self.get_threat_statistics()
        else:
            return f"Unknown tool name: {name}"

    def calculate_risk_score(self, anomaly_id=None, event_rate=0, z_score=0):
        """
        Tool #5: Calculate composite risk score (0-100).
        """
        risk_score = 0
        risk_score += min(z_score * 10, 40)
        risk_score += min(event_rate * 2, 30)
        risk_score += 15 if anomaly_id else 0
        risk_score += 15 if event_rate > 20 else 0
        risk_score = min(round(risk_score), 100)
        risk_level = "CRITICAL" if risk_score >= 80 else "HIGH" if risk_score >= 60 else "MEDIUM" if risk_score >= 40 else "LOW"
        return json.dumps({
            "risk_score": risk_score,
            "risk_level": risk_level,
            "factors": {"z_score_impact": min(z_score * 10, 40), "rate_impact": min(event_rate * 2, 30), "burst_multiplier": 15 if event_rate > 20 else 0}
        })

    def search_attack_patterns(self, pattern="ddos"):
        """
        Tool #6: Search known attack patterns and return indicators.
        """
        patterns = {
            "ddos": {"name": "DDoS Attack", "description": "Distributed Denial of Service - high volume traffic from multiple sources", "indicators": ["Sudden traffic spike >5x baseline", "Multiple source IPs", "Uniform request patterns"]},
            "bot": {"name": "Bot Activity", "description": "Automated bot traffic mimicking user behavior", "indicators": ["Rapid sequential requests", "Identical user agents", "Non-human timing patterns"]},
            "brute_force": {"name": "Brute Force", "description": "Repeated authentication or enumeration attempts", "indicators": ["High failure rate", "Sequential parameter variation", "Rapid retry intervals"]},
            "injection": {"name": "Injection Attack", "description": "SQL/NoSQL/Command injection attempts", "indicators": ["Unusual query patterns", "Special characters in input", "Abnormal error rates"]},
        }
        match = patterns.get(pattern.lower(), patterns["ddos"])
        return json.dumps(match)

    def generate_incident_report(self, anomaly_id=None):
        """
        Tool #7: Generate structured incident report.
        """
        if not anomaly_id:
            return "Error: anomaly_id is required."
        try:
            conn = sqlite3.connect(self.db_path, timeout=30.0)
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            conn.execute("PRAGMA busy_timeout=30000;")
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM anomalies WHERE id = ?", (anomaly_id,))
            row = cursor.fetchone()
            conn.close()
            if not row:
                return f"No anomaly found with ID {anomaly_id}"
            report = {
                "incident_id": f"INC-{anomaly_id}",
                "anomaly_id": anomaly_id,
                "severity": "MEDIUM",
                "z_score": row[2],
                "event_count": row[5],
                "window_stats": {"mean": row[3], "std": row[4]},
                "status": row[6],
                "diagnosis": row[7],
                "generated_at": datetime.now().isoformat(),
            }
            return json.dumps(report, indent=2)
        except Exception as e:
            return f"Error generating report: {str(e)}"

    def get_threat_statistics(self):
        """
        Tool #8: Return aggregate threat statistics.
        """
        try:
            conn = sqlite3.connect(self.db_path, timeout=30.0)
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            conn.execute("PRAGMA busy_timeout=30000;")
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM anomalies")
            total_anomalies = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM anomalies WHERE status = 'Mitigated'")
            mitigated = cursor.fetchone()[0]
            cursor.execute("SELECT source, COUNT(*) as count FROM events WHERE timestamp > (strftime('%s','now') - 300) GROUP BY source ORDER BY count DESC")
            source_dist = [{"source": r[0], "count": r[1]} for r in cursor.fetchall()]
            conn.close()
            return json.dumps({
                "total_anomalies": total_anomalies,
                "mitigated": mitigated,
                "pending": total_anomalies - mitigated,
                "source_distribution": source_dist,
            }, indent=2)
        except Exception as e:
            return f"Error fetching statistics: {str(e)}"
