# AI Usage & Solution Architecture Report

This report outlines the co-creation workflow of **Aegis** with the Google AI Studio assistant, detailing executed tasks, identified bugs/limitations, and the corresponding mitigation resolutions.

---

## 👥 Team Information (Mandatory Placeholders)

*   **Team Name:** [Insert Team Name]
*   **Team Members and Resumes:**
    1.  **[Member 1 Name]** - 10th: [xx%], 12th: [xx%], UG CGPA/Percentage: [x.xx / xx%]
    2.  **[Member 2 Name]** - 10th: [xx%], 12th: [xx%], UG CGPA/Percentage: [x.xx / xx%]
    3.  **[Member 3 Name]** - 10th: [xx%], 12th: [xx%], UG CGPA/Percentage: [x.xx / xx%]
    4.  **[Member 4 Name]** - 10th: [xx%], 12th: [xx%], UG CGPA/Percentage: [x.xx / xx%]
*   **Public GitHub Repository Link:** [Insert Repository Link]
*   **Demo Video (5-7 Minutes Loom/OBS Link):** [Insert Video Link]

---

## 🤖 AI Assistant Contributions

The AI Coding Assistant served as a Senior Architect and Software Systems Engineer. The specific prompts used during development are documented in [ai_prompts.md](file:///c:/Users/Mugilan/Downloads/aegis/ai_prompts.md). 

Tasks executed by the assistant:
1.  **SQLite Event Scheme Configuration & Storage (`storage/db.py` & `src/server_db.ts`):** Scaffolded relational schemas for transaction data tracking logs, alert logs, and ReAct agent steps.
2.  **Sliding Window Stats Engine (`detection/consumer.py` & `server.ts`):** Encapsulated mean, standard deviation, and dynamic Z-Score calculation boundaries inside high-fidelity continuous listeners.
3.  **Model Context Protocol Schema (`mcp_server.py` & `src/server_agent.ts`):** Outlined tools mapping schema to permit programmatic queries, firewall mitigations, and Discord warning transmissions.
4.  **Autonomous ReAct Agent Loop (`ai/agent_loop.py` & `src/server_agent.ts`):** Crafted reasoning state-machines displaying detailed Thought, Action, and Observation prints.
5.  **Interactive Full-Stack Web App Panel (`src/App.tsx` & `server.ts`):** Built a high-performance dark-themed React+Express dashboard showing live Area charts, settings adjusters, and live agent consoles.

---

## 🐞 Bugs, Limitations, and Resolution Strategies

Throughout implementation, several technical bottlenecks arose. Below is a breakdown of how the assistant and team engineered resolutions:

### 1. SQLite Concurrency Locking Conflicts (`database is locked`)
*   **Problem:** Standard SQLite connections throw `database is locked` exceptions when the background transaction generator thread (writing events at high speed) and the detector consumer thread (reading events for statistical window analysis) query the database simultaneously.
*   **AI Mistake:** Initially code instances opened basic, synchronous SQLite channels on standard connections.
*   **Resolution:** 
    1.  The team injected database initialization statements enabling **Write-Ahead-Logging (WAL) mode** (`PRAGMA journal_mode=WAL;`). This allows simultaneous readers and writers to access the database file cleanly without locks.
    2.  Increased connection checkout latency limits (`sqlite3.connect(db_path, timeout=30.0)`), giving heavy write bursts adequate buffers to clear queue targets safely.

### 2. Pytest Routing & Path Dependencies (`ModuleNotFoundError`)
*   **Problem:** Running pytest scripts or standalone subprocess commands threw path errors since folders like `detection` or `ai` were unable to naturally import sister roots (such as `config` or `mcp_server`).
*   **AI Mistake:** Subprocess spawned actions expected absolute native environmental folders to be mapped in relative formats.
*   **Resolution:** Injected sys paths manipulation directives at the top tier of all standalone Python routines (`sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))`), guaranteeing that no matter what working directory tests are called from, execution path coordinates bind successfully.

### 3. Z-Test Division-by-Zero (Zero-Variance Baselines)
*   **Problem:** If standard stream events are extremely steady (e.g. exactly 5 orders written every second), the calculated sample standard deviation is `0.0`. This results in division-by-zero exceptions (`ZeroDivisionError`) when calculating the Z-Score.
*   **AI Mistake:** Standard formula calculation did not safeguard the standard deviation divisor.
*   **Resolution:** Modified statistical detectors to explicitly evaluate divisor bounds:
    ```python
    if std_dev > 0:
        z_score = (current_count - mean) / std_dev
    else:
        z_score = 0.0
    ```
    This guarantees 100% mathematical stability under uniform baselines.
