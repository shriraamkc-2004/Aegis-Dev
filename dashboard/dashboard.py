import streamlit as st
import sqlite3
import pandas as pd
import time
import os
import random
from datetime import datetime

# Configure page settings
st.set_page_config(
    page_title="Aegis — Streaming Analytics",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Dark theme styling injections
st.markdown("""
<style>
    .main { background-color: #0d0f12; color: #e2e8f0; }
    .stApp { background-color: #0d0f12; }
    div[data-testid="stMetricValue"] { color: #fecdd3; font-family: monospace; }
    .metric-card {
        background-color: #1a1e24;
        border: 1px solid #2d3748;
        padding: 1.2rem;
        border-radius: 8px;
        margin-bottom: 1rem;
    }
    .status-active { color: #10b981; font-weight: bold; }
    .status-breach { color: #f43f5e; font-weight: bold; }
</style>
""", unsafe_allow_html=True)

# Database file accessor
mode = os.getenv("MODE")
if mode == "demo":
    raw_db_path = "storage/events_demo.db"
elif mode == "organization":
    raw_db_path = "storage/events_org.db"
else:
    import sys
    print(f"❌ [Fatal Error] Invalid MODE configuration: '{mode}'. Expected 'demo' or 'organization'.")
    sys.exit(1)

DB_PATH = os.path.abspath(raw_db_path) if os.path.isabs(raw_db_path) else os.path.abspath(os.path.join(os.getcwd(), raw_db_path))

def load_live_metrics():
    """
    Pulls recent metrics from events and anomalies database tables.
    """
    if not os.path.exists(DB_PATH):
        return {"opm": 0, "z_score": 0.0, "status": "Steady State", "active_threats": 0}
        
    try:
        conn = sqlite3.connect(DB_PATH, timeout=30.0)
        curr = conn.cursor()
        
        # 1. Orders Per Minute (count of orders in last 60s)
        cutoff = time.time() - 60
        curr.execute("SELECT COUNT(*) FROM events WHERE timestamp >= ?", (cutoff,))
        opm = curr.fetchone()[0]
        
        # 2. Get latest Z-Score / Anomaly activity
        curr.execute("SELECT id, z_score, status, timestamp FROM anomalies ORDER BY id DESC LIMIT 1")
        last_anom = curr.fetchone()
        
        status = "Steady State"
        last_z = 0.0
        
        if last_anom:
            last_z = last_anom[1]
            time_since = time.time() - last_anom[3]
            if time_since < 20: # breach in last 20 seconds
                status = "🚨 ANOMALY BREED CHECK"
            elif last_anom[2] == "Pending Mitigation":
                status = "🛡️ CONTAINMENT IN-PROGRESS"
                
        # 3. Running total of registered breaches
        curr.execute("SELECT COUNT(*) FROM anomalies WHERE status = 'Pending Mitigation'")
        active_threats = curr.fetchone()[0]
        
        conn.close()
        return {"opm": opm, "z_score": last_z, "status": status, "active_threats": active_threats}
    except Exception:
        return {"opm": 0, "z_score": 0.0, "status": "Steady State", "active_threats": 0}

# Application Title
st.title("🛡️ Aegis: Streaming Agent Anomaly System")
st.caption("Real-time Sliding Window Statistical Anomaly Detection & Autonomous ReAct Agent Containment Dashboard")

# Navigation/Controls Sidebar
st.sidebar.markdown("### ⚙️ Engine Configurations")
window_size = st.sidebar.slider("Sliding Window Size (seconds)", 30, 300, 60)
z_score_thresh = st.sidebar.slider("Z-Score Spike Sensitivity Threshold", 2.0, 6.0, 3.0, step=0.1)

st.sidebar.markdown("---")
st.sidebar.markdown("### 🤖 Autonomous Agent Params")
st.sidebar.info(f"Using Action loop via: **Llama 3.1 (Ollama)** with Google Gemini API free-tier fallback.")

st.sidebar.markdown("---")
# Manually inject simulation spike
if st.sidebar.button("💥 Simulate Burst Attack (Inject 25 Orders)", help="Triggers manual high-frequency traffic spike to test detector"):
    try:
        conn = sqlite3.connect(DB_PATH, timeout=30.0)
        curr = conn.cursor()
        surge_source = random.choice(["web", "mobile"])
        t_now = time.time()
        for i in range(25):
            curr.execute(
                "INSERT INTO events (event_type, order_id, timestamp, source) VALUES (?, ?, ?, ?)",
                ("order_placed", f"ORD{random.randint(100000, 999999)}", t_now, surge_source)
            )
        conn.commit()
        conn.close()
        st.sidebar.success("Injected 25 orders successfully! Wait 1-2 seconds for detection.")
    except Exception as e:
        st.sidebar.error(f"Injected transaction write crash: {e}")

# Main live visualization pane
col1, col2, col3, col4 = st.columns(4)
metrics = load_live_metrics()

with col1:
    st.metric("Orders Per Minute (OPM)", f"{metrics['opm']} count", "+5%" if metrics['opm'] > 10 else "0%")
with col2:
    st.metric("Latest Event Z-Score", f"{metrics['z_score']:.2f}")
with col3:
    st.metric("Pending Containments", f"{metrics['active_threats']} alerts")
with col4:
    color_class = "status-breach" if "🚨" in metrics["status"] else "status-active"
    st.markdown(f"""
    <div class="metric-card">
        <p style="margin:0;font-size:0.85rem;color:#718096;text-transform:uppercase;">Global System Health</p>
        <p class="{color_class}" style="margin:0.2rem 0 0 0;font-size:1.4rem;">{metrics['status']}</p>
    </div>
    """, unsafe_allow_html=True)

# Real time Line Chart
st.markdown("### 📈 Live Sliding Window Event Velocity")
try:
    if os.path.exists(DB_PATH):
        conn = sqlite3.connect(DB_PATH, timeout=30.0)
        # Pull transactional load of the last 120s
        df = pd.read_sql_query("""
            SELECT CAST(timestamp as INTEGER) as sec, count(*) as count 
            FROM events 
            WHERE timestamp >= (strftime('%s', 'now') - 120) 
            GROUP BY sec 
            ORDER BY sec ASC
        """, conn)
        conn.close()
        
        if not df.empty:
            df['Time'] = df['sec'].apply(lambda x: datetime.fromtimestamp(x).strftime('%H:%M:%S'))
            st.line_chart(df.set_index('Time')['count'], height=250)
        else:
            st.info("No transaction telemetry flowing yet. Start your event producer script to feed real-time patterns.")
    else:
        st.warning("SQLite database not created. Please boot your background producer and detection processes.")
except Exception:
    st.error("Error drawing live chart.")

# Split Bottom Screen - Anomaly Feeds vs ReAct Traces
bottom_col1, bottom_col2 = st.columns([1, 1])

with bottom_col1:
    st.markdown("### 🚨 Detected Anomalies Feed")
    try:
        if os.path.exists(DB_PATH):
            conn = sqlite3.connect(DB_PATH, timeout=30.0)
            anom_df = pd.read_sql_query("""
                SELECT id as ID, timestamp, z_score as Z_Score, event_count as Event_Count, status as Status, diagnosis as AI_Diagnosis 
                FROM anomalies 
                ORDER BY ID DESC 
                LIMIT 5
            """, conn)
            conn.close()
            
            if not anom_df.empty:
                anom_df['Time'] = anom_df['timestamp'].apply(lambda x: datetime.fromtimestamp(x).strftime('%Y-%m-%d %H:%M:%S'))
                for index, row in anom_df.iterrows():
                    box_color = "#2d1a1e" if row["Status"] == "Pending Mitigation" else "#1a2d21"
                    border_color = "#f43f5e" if row["Status"] == "Pending Mitigation" else "#10b981"
                    st.markdown(f"""
                    <div style="background-color: {box_color}; padding: 1rem; border-left: 5px solid {border_color}; border-radius: 4px; margin-bottom: 0.8rem;">
                        <h4 style="margin: 0; display:flex; justify-content: space-between;">
                            <span>Anomaly ID #{row['ID']} ({row['Status']})</span>
                            <span style="font-family: monospace;">Z-Score: {row['Z_Score']:.2f}</span>
                        </h4>
                        <p style="margin: 0.3rem 0; font-size: 0.9rem; color: #cbd5e0;">Time: {row['Time']} | Spike Count: {row['Event_Count']} transactions/sec</p>
                        <p style="margin: 0; font-style: italic; color: #9cf; font-size: 0.9rem;"><strong>AI Diagnostic Mitigation:</strong> {row['AI_Diagnosis']}</p>
                    </div>
                    """, unsafe_allow_html=True)
            else:
                st.info("Zero system anomalies logged in this current cycle. Systems operating in normal range.")
    except Exception as err:
        st.error(f"Error accessing database feeds: {err}")

with bottom_col2:
    st.markdown("### 🤖 Autonomous Agent Trace Explorer")
    try:
        if os.path.exists(DB_PATH):
            conn = sqlite3.connect(DB_PATH, timeout=30.0)
            # Find the latest anomaly ID to show traces
            latest_id_df = pd.read_sql_query("SELECT id FROM anomalies ORDER BY id DESC LIMIT 1", conn)
            
            if not latest_id_df.empty:
                anom_id_focus = latest_id_df.iloc[0]["id"]
                st.write(f"Displaying reasoning steps for **Anomaly ID #{anom_id_focus}**:")
                
                trace_df = pd.read_sql_query("""
                    SELECT step as Step, type as Step_Type, timestamp, content as Reasoning_Details
                    FROM agent_logs
                    WHERE anomaly_id = ?
                    ORDER BY Step ASC, id ASC
                """, conn, params=(int(anom_id_focus),))
                
                if not trace_df.empty:
                    for index, r in trace_df.iterrows():
                        step_type = r["Step_Type"]
                        icon = "🧠"
                        if step_type == "Action": icon = "⚙️"
                        elif step_type == "Observation": icon = "👁️"
                        elif step_type == "Final Response": icon = "🏁"
                        
                        avatar_url = ""
                        with st.chat_message(name=step_type.lower(), avatar=icon):
                            st.markdown(f"**{step_type} Step {r['Step']}**")
                            st.write(r["Reasoning_Details"])
                else:
                    st.info(f"ReAct Agent trace logs are being compiled for #{anom_id_focus}... Please wait.")
            else:
                st.info("No traces available yet. Real-time trace explorer is vacant.")
            conn.close()
    except Exception as trace_err:
        st.error(f"Error displaying traces: {trace_err}")

# Auto-reloader script info
st.markdown("---")
st.caption("🔁 Streamlit updates database reads automatically. Use manual page refresh or set auto-refresh in your dashboard view.")
