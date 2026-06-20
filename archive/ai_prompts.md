# Key Prompts Used During Development

This document logs the core prompts and instructions provided to AI Coding Assistants during the co-creation of the **Aegis** system.

---

## 💾 1. Database and Data Storage Schema Development
**Prompt:**
```text
Write a Python script `storage/db.py` to manage our SQLite database connections safely under multi-threaded execution environments.
1. Implement thread-local connection pooling/caching to avoid sqlite3 concurrency errors.
2. Initialize three core tables:
   - `events` (id, event_type, order_id, timestamp, source)
   - `anomalies` (id, timestamp, z_score, window_mean, window_std, event_count, status, diagnosis)
   - `agent_logs` (id, anomaly_id, timestamp, step, type, content)
3. Ensure Write-Ahead-Logging (WAL) mode is explicitly enabled (`PRAGMA journal_mode=WAL;`) to handle high-frequency concurrent writes.
4. Implement helper methods for inserting events, anomalies, updating anomaly statuses, and logging reasoning steps.
```

---

## 📈 2. Sliding Window Statistical Anomaly Detector
**Prompt:**
```text
Create a sliding window statistical detector engine in Python (`detection/consumer.py`) and TypeScript (`server.ts`):
1. The detector must run continuously, querying recent database events in 1-second bins.
2. Calculate the sample mean and standard deviation of counts across a sliding window (e.g., past 60 seconds).
3. Compute the current Z-Score safely:
   - If the standard deviation is 0 (uniform event stream), make sure to return 0.0 instead of throwing a division-by-zero exception (ZeroDivisionError).
4. If the Z-Score breaches a specified threshold (e.g., Z > 3.0) and exceeds a minimum event rate, register a new anomaly record in SQLite.
5. In Python, spawn a new background subprocess: `subprocess.Popen([sys.executable, "ai/agent_loop.py", str(anomaly_id)])` to initiate the ReAct mitigation loop.
6. In TypeScript, execute `runServerAgentLoop(anomalyId, currentEventRate)`.
```

---

## 🛡️ 3. Model Context Protocol (MCP) Server
**Prompt:**
```text
Develop an MCP (Model Context Protocol) tool provider server in Python (`mcp_server.py`) and equivalent mock functions in TypeScript (`src/server_agent.ts`):
1. Expose four standard tools to reasoning agents:
   - `query_database`: Executes read-only SELECT queries on the SQLite event store to examine source distributions. Reject any query that does not start with SELECT for security.
   - `read_system_logs`: Inspects the last 15 lines of system logs to review platform uptime and status.
   - `mitigate_anomaly`: Applies load-balancer throttling on specified sources (e.g., 'web' or 'mobile') and dynamically scales the Z-Score threshold to prevent alert fatigue.
   - `trigger_discord_alert`: Dispatches real-time message reports to a configured Discord webhook.
2. Structure the `list_tools()` function to return standard MCP JSON schemas representing these tools and parameters.
```

---

## 🤖 4. ReAct Reasoning and Decision Loop
**Prompt:**
```text
Write a robust ReAct (Reasoning and Action) loop in Python (`ai/agent_loop.py`) and TypeScript (`src/server_agent.ts`):
1. Take an `anomaly_id` argument to initiate investigation.
2. Read the `GEMINI_API_KEY` from the environment.
3. If the key is present, construct a system prompt detailing the ReAct flow:
   - Thought: <reasoning steps>
   - Action: <json schema of the tool to invoke: {"name": "query_database", "arguments": {...}}>
   - Observation: <result returned by executing that local tool>
   - Final Response: <concluding diagnostic report and mitigation status>
4. Run up to 4 iterations of this loop, querying the Gemini API (specifically `gemini-3.5-flash` or REST endpoints).
5. If the key is missing or invalid, fall back to a deterministic, high-fidelity rule-based simulation of the ReAct steps that calls the ACTUAL local MCP tools to perform the query, block traffic, alert Discord, and output the Final Response.
6. Persist every step of the ReAct log into the `agent_logs` SQLite table.
```

---

## 🖥️ 5. Full-Stack Web App Dashboard and Control Panel
**Prompt:**
```text
Create a React frontend dashboard (`src/App.tsx`) and Express server (`server.ts`):
1. Design a premium, high-fidelity dark UI using Tailwind CSS v4 and Outfit/Inter fonts.
2. The UI must contain:
   - Live sliding window charts showing events per second using Recharts AreaCharts.
   - Metrics cards for live Z-score, sliding window mean, standard deviation, and active threats count.
   - A sidebar with interactive input controls to adjust the Z-Score threshold, sliding window size, and event speed live.
   - A button to manually inject order spikes ("Trigger Manual Surge Simulation") to immediately test detection.
   - An anomalies list displaying the database logs. Clicking an anomaly must display its full co-created ReAct agent logs step-by-step (Thought -> Action -> Observation -> Final Response) with custom stylized badges and cards.
3. Serve production assets statically, and hook up Vite middlewares for hot-reloaded development mode.
```
