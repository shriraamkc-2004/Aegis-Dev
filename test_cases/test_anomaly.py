import unittest
import sys
import os
import sqlite3
import time

# Incorporate root in path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detection.consumer import calculate_stats
from storage.db import init_db, insert_event, insert_anomaly, insert_agent_log, insert_incident, update_incident_status, close_db_connection
from mcp_server import MCPServer
from ai.agent_loop import run_react_agent_loop

class TestAnomalyAegis(unittest.TestCase):
    
    def setUp(self):
        self.test_db = "storage/test_events.db"
        # Ensure database is freshly created/reset
        close_db_connection()
        if os.path.exists(self.test_db):
            try:
                os.remove(self.test_db)
            except Exception:
                pass
        init_db(self.test_db)
        
    def tearDown(self):
        close_db_connection()
        if os.path.exists(self.test_db):
            try:
                os.remove(self.test_db)
            except Exception:
                pass

    def test_z_score_calculations_standard(self):
        """
        Verify statistical formulas for rolling averages and standard deviations.
        """
        window = [10, 12, 11, 9, 13]
        mean, std = calculate_stats(window)
        
        self.assertAlmostEqual(mean, 11.0)
        self.assertAlmostEqual(std, 1.5811388300841898) # Sample std dev

    def test_z_score_with_zero_variance(self):
        """
        Z-score must handle situations with 0 variance nicely without dividing by zero.
        """
        window = [10, 10, 10, 10, 10]
        mean, std = calculate_stats(window)
        
        self.assertEqual(mean, 10.0)
        self.assertEqual(std, 0.0)

    def test_database_insertions(self):
        """
        Confirm that SQLite registers stream events and anomalies correctly.
        """
        # Test Event Write
        evt_id = insert_event("order_placed", "ORD_TEST_01", time.time(), "web", db_path=self.test_db)
        self.assertTrue(evt_id > 0)
        
        # Test Anomaly Write
        anom_id = insert_anomaly(time.time(), 4.21, 10.0, 1.5, 25, db_path=self.test_db)
        self.assertTrue(anom_id > 0)
        
        # Verify schema reads
        conn = sqlite3.connect(self.test_db)
        cursor = conn.cursor()
        cursor.execute("SELECT order_id FROM events WHERE id = ?", (evt_id,))
        self.assertEqual(cursor.fetchone()[0], "ORD_TEST_01")
        
        cursor.execute("SELECT z_score FROM anomalies WHERE id = ?", (anom_id,))
        self.assertEqual(cursor.fetchone()[0], 4.21)
        conn.close()

    def test_mcp_server_tools_and_query_database(self):
        """
        Asserts that the MCP engine exposes all 8 tools and query_database works.
        """
        mcp = MCPServer(db_path=self.test_db)
        
        # Check tool definitions - should now have 8 tools
        tools = mcp.list_tools()
        self.assertEqual(len(tools), 8)
        tool_names = [t["name"] for t in tools]
        self.assertIn("query_database", tool_names)
        self.assertIn("mitigate_anomaly", tool_names)
        self.assertIn("calculate_risk_score", tool_names)
        self.assertIn("search_attack_patterns", tool_names)
        self.assertIn("generate_incident_report", tool_names)
        self.assertIn("get_threat_statistics", tool_names)
        
        # Populate custom dummy data
        insert_event("order_placed", "ORD_BOT_01", time.time(), "mobile", db_path=self.test_db)
        insert_event("order_placed", "ORD_BOT_02", time.time(), "mobile", db_path=self.test_db)
        
        # Run MCP query database tool
        res_json = mcp.query_database("SELECT count(*) as total FROM events WHERE source = 'mobile'")
        import json
        res_data = json.loads(res_json)
        self.assertEqual(res_data[0]["total"], 2)

    def test_mcp_mitigations(self):
        """
        Validate MCP containment calls.
        """
        mcp = MCPServer(db_path=self.test_db)
        res = mcp.mitigate_anomaly(ip_or_source="web", raise_z_threshold=5.0)
        self.assertIn("throttled/blocked source layer 'web'", res)
        self.assertIn("adjusted Z-Score threshold setting to 5.0", res)

    def test_react_agent_deterministic_workflow(self):
        """
        Assert that calling run_react_agent_loop creates standard thoughts, action steps and final answers.
        """
        anom_id = insert_anomaly(time.time(), 5.12, 8.0, 1.2, 35, db_path=self.test_db)
        
        # Execute the Agent Loop
        run_react_agent_loop(anom_id, db_path=self.test_db)
        
        # Fetch trace results from logs
        conn = sqlite3.connect(self.test_db)
        cursor = conn.cursor()
        cursor.execute("SELECT type, content FROM agent_logs WHERE anomaly_id = ? ORDER BY id ASC", (anom_id,))
        logs = cursor.fetchall()
        conn.close()
        
        # Logs should be written for Thought, Action, Observation, Final Response
        self.assertTrue(len(logs) >= 4)
        log_types = [l[0] for l in logs]
        self.assertIn("Thought", log_types)
        self.assertIn("Action", log_types)
        self.assertIn("Observation", log_types)
        self.assertIn("Final Response", log_types)

    def test_mcp_calculate_risk_score(self):
        """
        Validate MCP risk score calculation returns valid JSON with score and level.
        """
        import json
        mcp = MCPServer(db_path=self.test_db)
        result = mcp.calculate_risk_score(anomaly_id=1, event_rate=25, z_score=5.0)
        data = json.loads(result)
        self.assertIn("risk_score", data)
        self.assertIn("risk_level", data)
        self.assertGreaterEqual(data["risk_score"], 0)
        self.assertLessEqual(data["risk_score"], 100)
        self.assertIn(data["risk_level"], ["LOW", "MEDIUM", "HIGH", "CRITICAL"])

    def test_mcp_search_attack_patterns(self):
        """
        Validate MCP attack pattern search returns known patterns.
        """
        import json
        mcp = MCPServer(db_path=self.test_db)
        result = mcp.search_attack_patterns("ddos")
        data = json.loads(result)
        self.assertEqual(data["name"], "DDoS Attack")
        self.assertIn("indicators", data)
        self.assertTrue(len(data["indicators"]) > 0)

    def test_mcp_get_threat_statistics(self):
        """
        Validate MCP threat statistics returns aggregate data.
        """
        import json
        mcp = MCPServer(db_path=self.test_db)
        # Insert some test data
        insert_event("order_placed", "ORD_STAT_01", time.time(), "web", db_path=self.test_db)
        insert_anomaly(time.time(), 4.5, 10.0, 1.5, 20, db_path=self.test_db)
        result = mcp.get_threat_statistics()
        data = json.loads(result)
        self.assertIn("total_anomalies", data)
        self.assertGreaterEqual(data["total_anomalies"], 1)

    # ============================
    # HAPPY PATH TESTS
    # ============================
    
    def test_happy_path_incident_creation_on_anomaly(self):
        """
        Happy Path: When an anomaly peak is detected, an incident record should be
        automatically created in the incidents table linked to the anomaly.
        """
        # Insert an anomaly
        anom_id = insert_anomaly(time.time(), 5.5, 8.0, 1.2, 30, db_path=self.test_db)
        self.assertTrue(anom_id > 0)
        
        # Create a linked incident
        inc_id = insert_incident(
            anom_id,
            "Test Incident",
            "Test description for anomaly spike",
            "HIGH",
            db_path=self.test_db
        )
        self.assertTrue(inc_id > 0)
        
        # Verify the incident is in the database
        conn = sqlite3.connect(self.test_db)
        cursor = conn.cursor()
        cursor.execute("SELECT id, anomaly_id, title, severity, status FROM incidents WHERE id = ?", (inc_id,))
        row = cursor.fetchone()
        conn.close()
        
        self.assertIsNotNone(row)
        self.assertEqual(row[1], anom_id)
        self.assertEqual(row[2], "Test Incident")
        self.assertEqual(row[3], "HIGH")
        self.assertEqual(row[4], "OPEN")

    def test_happy_path_incident_update_on_mitigation(self):
        """
        Happy Path: When the AI agent mitigates an anomaly, the linked incident
        should be updated with root cause, AI diagnosis, and resolution.
        """
        # Setup: anomaly + incident
        anom_id = insert_anomaly(time.time(), 4.8, 10.0, 1.5, 25, db_path=self.test_db)
        inc_id = insert_incident(anom_id, "Mitigation Test", "Desc", "MEDIUM", db_path=self.test_db)
        
        # Simulate AI agent updating the incident
        update_incident_status(
            anom_id, "MITIGATED",
            "Traffic spike from mobile sources",
            "AI analyzed and throttled mobile traffic",
            "Source blocked, threshold raised",
            "Monitor for recurrence",
            db_path=self.test_db
        )
        
        # Verify update
        conn = sqlite3.connect(self.test_db)
        cursor = conn.cursor()
        cursor.execute("SELECT status, root_cause, ai_diagnosis, resolution FROM incidents WHERE id = ?", (inc_id,))
        row = cursor.fetchone()
        conn.close()
        
        self.assertEqual(row[0], "MITIGATED")
        self.assertIn("mobile", row[1])
        self.assertIn("AI analyzed", row[2])
        self.assertIn("blocked", row[3])

    def test_happy_path_agent_loop_creates_incident_trace(self):
        """
        Happy Path: Full end-to-end agent loop creates anomaly, incident, agent logs,
        and updates both anomaly and incident status.
        """
        # Create anomaly + incident
        anom_id = insert_anomaly(time.time(), 5.12, 8.0, 1.2, 35, db_path=self.test_db)
        inc_id = insert_incident(anom_id, "E2E Test", "Full workflow test", "HIGH", db_path=self.test_db)
        
        # Run the agent loop
        run_react_agent_loop(anom_id, db_path=self.test_db)
        
        # Verify: agent logs exist
        conn = sqlite3.connect(self.test_db)
        cursor = conn.cursor()
        cursor.execute("SELECT type FROM agent_logs WHERE anomaly_id = ?", (anom_id,))
        log_types = [r[0] for r in cursor.fetchall()]
        
        # Verify: anomaly status updated to Mitigated
        cursor.execute("SELECT status FROM anomalies WHERE id = ?", (anom_id,))
        anom_status = cursor.fetchone()[0]
        
        # Verify: incident status updated to MITIGATED
        cursor.execute("SELECT status FROM incidents WHERE id = ?", (inc_id,))
        inc_status = cursor.fetchone()[0]
        conn.close()
        
        self.assertIn("Thought", log_types)
        self.assertIn("Action", log_types)
        self.assertIn("Observation", log_types)
        self.assertIn("Final Response", log_types)
        self.assertEqual(anom_status, "Mitigated")
        self.assertEqual(inc_status, "MITIGATED")

    def test_happy_path_sample_data_loading(self):
        """
        Happy Path: Sample data files can be loaded and replayed into the database.
        """
        from stream.producer import load_sample_data
        
        # Test loading all three sample files
        for sample_file in ["normal_sample.json", "anomaly_sample.json", "mixed_sample.json"]:
            events = load_sample_data(sample_file)
            self.assertGreater(len(events), 0, f"Failed to load {sample_file}")
            
            # Verify events have required fields
            for evt in events:
                self.assertIn("event", evt)
                self.assertIn("order_id", evt)
                self.assertIn("timestamp", evt)
                self.assertIn("source", evt)

    def test_happy_path_sample_replay_persists_events(self):
        """
        Happy Path: Replayed sample data correctly persists events to the database.
        """
        from stream.producer import load_sample_data, replay_sample_data
        
        events = load_sample_data("mixed_sample.json")
        self.assertGreater(len(events), 0)
        
        # Replay into test database
        replay_sample_data(events, db_path=self.test_db, speed_multiplier=10.0)
        
        # Verify events were persisted
        conn = sqlite3.connect(self.test_db)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM events")
        count = cursor.fetchone()[0]
        conn.close()
        
        self.assertEqual(count, len(events))

    def test_happy_path_mcp_all_tools_functional(self):
        """
        Happy Path: All 8 MCP tools are exposed and return valid results.
        """
        import json
        mcp = MCPServer(db_path=self.test_db)
        
        # Seed test data
        insert_event("order_placed", "ORD_MCP_01", time.time(), "web", db_path=self.test_db)
        anom_id = insert_anomaly(time.time(), 4.0, 10.0, 2.0, 20, db_path=self.test_db)
        
        # Test each tool
        result = mcp.call_tool("query_database", {"sql_query": "SELECT COUNT(*) as cnt FROM events"})
        data = json.loads(result)
        self.assertEqual(data[0]["cnt"], 1)
        
        result = mcp.call_tool("read_system_logs", {})
        self.assertIsInstance(result, str)
        
        result = mcp.call_tool("mitigate_anomaly", {"ip_or_source": "web", "raise_z_threshold": 4.0})
        self.assertIn("throttled", result)
        
        result = mcp.call_tool("trigger_discord_alert", {"message": "test"})
        self.assertIsInstance(result, str)
        
        result = mcp.call_tool("calculate_risk_score", {"anomaly_id": anom_id, "event_rate": 20, "z_score": 4.0})
        data = json.loads(result)
        self.assertIn("risk_score", data)
        
        result = mcp.call_tool("search_attack_patterns", {"pattern": "bot"})
        data = json.loads(result)
        self.assertEqual(data["name"], "Bot Activity")
        
        result = mcp.call_tool("generate_incident_report", {"anomaly_id": anom_id})
        data = json.loads(result)
        self.assertIn("incident_id", data)
        
        result = mcp.call_tool("get_threat_statistics", {})
        data = json.loads(result)
        self.assertIn("total_anomalies", data)

    def test_scenario_a_brute_force(self):
        """
        Scenario A: Inject 50 authentication failures. Expected: Possible Brute Force Activity
        """
        from detections.threat_classifier import ThreatClassifier
        t = time.time()
        for i in range(50):
            insert_event("failed_login", f"FAIL_{i}", t, "web", db_path=self.test_db)
        
        classifier = ThreatClassifier(db_path=self.test_db)
        threat, confidence, rec = classifier.classify(t, 55, 4.0)
        self.assertEqual(threat, "Possible Brute Force Activity")
        self.assertGreaterEqual(confidence, 65.0)

    def test_scenario_b_ddos(self):
        """
        Scenario B: Sustained high-volume request bursts. Expected: Possible DDoS Activity
        """
        from detections.threat_classifier import ThreatClassifier
        t = time.time()
        classifier = ThreatClassifier(db_path=self.test_db)
        threat, confidence, rec = classifier.classify(t, 25, 5.0)
        self.assertEqual(threat, "Possible DDoS Activity")
        self.assertGreaterEqual(confidence, 65.0)

    def test_scenario_c_service_failure(self):
        """
        Scenario C: Missing heartbeat events or sudden event drops. Expected: Possible Service Failure
        """
        from detections.threat_classifier import ThreatClassifier
        t = time.time()
        insert_event("heartbeat_miss", "HB_01", t, "internal", db_path=self.test_db)
        classifier = ThreatClassifier(db_path=self.test_db)
        threat, confidence, rec = classifier.classify(t, 1, 0.5)
        self.assertEqual(threat, "Possible Service Failure")
        self.assertGreaterEqual(confidence, 65.0)

    def test_scenario_d_data_exfiltration(self):
        """
        Scenario D: Large outbound transfer patterns. Expected: Possible Data Exfiltration
        """
        from detections.threat_classifier import ThreatClassifier
        t = time.time()
        insert_event("data_transfer_exfil", "EXFIL_01", t, "api", db_path=self.test_db)
        classifier = ThreatClassifier(db_path=self.test_db)
        threat, confidence, rec = classifier.classify(t, 5, 2.0)
        self.assertEqual(threat, "Possible Data Exfiltration")
        self.assertGreaterEqual(confidence, 65.0)

    def test_scenario_e_insider_threat(self):
        """
        Scenario E: Privileged configuration changes. Expected: Possible Insider Threat
        """
        from detections.threat_classifier import ThreatClassifier
        t = time.time()
        insert_event("privileged_config_change", "ADMIN_01", t, "console", db_path=self.test_db)
        classifier = ThreatClassifier(db_path=self.test_db)
        threat, confidence, rec = classifier.classify(t, 5, 2.0)
        self.assertEqual(threat, "Possible Insider Threat")
        self.assertGreaterEqual(confidence, 65.0)

    def test_discord_enrichment_payload_structure(self):
        """
        Verify that trigger_anomaly_discord_alert correctly retrieves and format-verifies
        severity, hybrid score, possible threat, threat confidence, recommendation, and Gemini summary.
        """
        # Create anomaly
        anom_id = insert_anomaly(time.time(), 5.12, 8.0, 1.2, 35, db_path=self.test_db)
        
        # Create incident with all enriched fields
        inc_id = insert_incident(
            anom_id,
            "Discord Enrichment Test",
            "Checking fields are forwarded",
            "CRITICAL",
            possible_threat="Possible DDoS Activity",
            threat_confidence=85.0,
            recommendation="Apply rate limits",
            db_path=self.test_db
        )
        
        # Update incident status with Gemini summary
        update_incident_status(
            anom_id,
            "MITIGATED",
            "Root cause text",
            "AI diagnosis",
            "Resolution text",
            "Apply rate limits",
            db_path=self.test_db
        )
        
        # Manually store gemini_summary in the db to simulate Gemini layer
        conn = sqlite3.connect(self.test_db)
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE incidents SET gemini_summary = ? WHERE anomaly_id = ?",
            ("This is a Gemini summary.", anom_id)
        )
        # Set a test hybrid score in anomalies
        cursor.execute(
            "UPDATE anomalies SET hybrid_score = 0.87 WHERE id = ?",
            (anom_id,)
        )
        conn.commit()
        conn.close()
        
        # Mock send_discord_webhook to capture the payload
        import alerts.discord_alert
        original_send = alerts.discord_alert.send_discord_webhook
        
        captured = {}
        def mock_send(webhook_url, message, embed_data=None):
            captured['url'] = webhook_url
            captured['message'] = message
            captured['embed'] = embed_data
            return True
            
        alerts.discord_alert.send_discord_webhook = mock_send
        
        try:
            res = alerts.discord_alert.trigger_anomaly_discord_alert(
                "https://discord.mock/webhook",
                anom_id,
                z_score=5.12,
                order_count=35,
                mean=8.0,
                std=1.2,
                db_path=self.test_db
            )
            
            self.assertTrue(res)
            self.assertIn("🚨 INCIDENT ALERT", captured['message'])
            self.assertIn("Severity: CRITICAL", captured['message'])
            self.assertIn("Hybrid Score: 0.87", captured['message'])
            self.assertIn("Possible Threat: Possible DDoS Activity", captured['message'])
            self.assertIn("Threat Confidence: 85.0%", captured['message'])
            self.assertIn("Recommendation: Apply rate limits", captured['message'])
            self.assertIn("Gemini Summary: This is a Gemini summary.", captured['message'])
            
            # Verify fields in the embed as well
            embed = captured['embed']
            self.assertEqual(embed['title'], "🚨 INCIDENT ALERT")
            
            field_names = [f['name'] for f in embed['fields']]
            self.assertIn("Severity", field_names)
            self.assertIn("Hybrid Score", field_names)
            self.assertIn("Possible Threat", field_names)
            self.assertIn("Threat Confidence", field_names)
            self.assertIn("Recommendation", field_names)
            self.assertIn("Gemini Summary", field_names)
            
        finally:
            alerts.discord_alert.send_discord_webhook = original_send

    def test_discord_pii_masking_safeguard(self):
        """
        Verify that outbound Discord alerts dynamically mask emails and IP addresses
        to comply with cyber-law requirements.
        """
        import alerts.discord_alert
        raw_text = "Send alert for admin@domain.com from IP 10.0.0.1"
        masked = alerts.discord_alert.mask_pii(raw_text)
        self.assertEqual(masked, "Send alert for a***n@d***.com from IP 10.0.*.*")
        
        # Test username explicitly
        username_raw = "administrator"
        username_masked = alerts.discord_alert.mask_pii(username_raw, val_type="username")
        self.assertEqual(username_masked, "a***********r")

if __name__ == "__main__":
    unittest.main()