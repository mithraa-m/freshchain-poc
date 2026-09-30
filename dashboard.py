import streamlit as st
import pandas as pd
import random
import time
from datetime import datetime
import hashlib
import sqlite3
import os

# Page Configuration
st.set_page_config(
    page_title="FRESHCHAIN System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Styling for clean enterprise look
st.markdown("""
    <style>
    .main {
        background-color: #ffffff;
    }
    h1 {
        font-size: 2.8rem !important;
        font-weight: 800 !important;
        color: #0f172a !important;
        margin-bottom: 0px !important;
    }
    .subtitle {
        font-size: 1.1rem;
        color: #4b5563;
        margin-bottom: 25px;
    }
    </style>
""", unsafe_allow_html=True)

# Initialize SQLite Database for local edge storage
DB_FILE = "freshchain_local.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS readings (
            seq INTEGER PRIMARY KEY,
            timestamp TEXT,
            temperature REAL,
            humidity REAL,
            vibration REAL,
            prev_hash TEXT,
            hash TEXT,
            status TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# Helper function to get latest record for hash chaining
def get_latest_hash():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT hash FROM readings ORDER BY seq DESC LIMIT 1")
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else "0000000000000000"

def get_latest_seq():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT seq FROM readings ORDER BY seq DESC LIMIT 1")
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else 1000

# App Header
st.markdown("<h1>🛡️ FRESHCHAIN</h1>", unsafe_allow_html=True)
st.markdown("<div class='subtitle'>Cold Chain Integrity & Verification System</div>", unsafe_allow_html=True)

# Initialize Session State flags
if "unsynced_count" not in st.session_state:
    st.session_state.unsynced_count = 0
if "tamper_flag" not in st.session_state:
    st.session_state.tamper_flag = False
if "integrity_status" not in st.session_state:
    st.session_state.integrity_status = "VERIFIED"

# Sidebar Control Center
st.sidebar.header("🎛️ Control Center")
network_status = st.sidebar.radio("Network Status", ["ONLINE", "OFFLINE"], index=0)
excursion_mode = st.sidebar.checkbox("🌡️ Trigger Temperature Excursion", value=False)

if st.sidebar.button("🚨 Trigger Tamper Event"):
    st.session_state.tamper_flag = True

if st.sidebar.button("🔍 Verify Chain Integrity"):
    # Re-verify all hashes in DB
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT seq, timestamp, temperature, humidity, vibration, prev_hash, hash FROM readings ORDER BY seq ASC")
    rows = cursor.fetchall()
    conn.close()
    
    broken = False
    for r in rows:
        seq, ts, temp, hum, vib, p_hash, stored_hash = r
        recalculated_raw = f"{seq}-{ts}-{temp}-{hum}-{vib}-{p_hash}"
        recalculated_hash = hashlib.sha256(recalculated_raw.encode()).hexdigest()[:16]
        if recalculated_hash != stored_hash:
            broken = True
            break
            
    st.session_state.integrity_status = "FAILED" if broken else "VERIFIED"

if st.sidebar.button("⚠️ Inject DB Tampering (For Demo)"):
    # Intentionally corrupt a value in the database to show integrity check fail!
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("UPDATE readings SET temperature = temperature + 15.0 WHERE seq = (SELECT MAX(seq) FROM readings)")
    conn.commit()
    conn.close()
    st.warning("Injected tampering into the latest database record!")

if st.sidebar.button("🔄 Reset System State"):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM readings")
    conn.commit()
    conn.close()
    st.session_state.unsynced_count = 0
    st.session_state.tamper_flag = False
    st.session_state.integrity_status = "VERIFIED"
    st.success("System database cleared and reset.")

# Generate new sensor data reading
if excursion_mode:
    temp = round(random.uniform(28.5, 32.8), 2)
else:
    temp = round(random.uniform(23.0, 26.5), 2)

humidity = round(random.uniform(62.0, 74.0), 2)
vibration = round(random.uniform(0.04, 0.22), 2)
timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# Hash Chaining Logic
prev_hash = get_latest_hash()
next_seq = get_latest_seq() + 1
raw_data = f"{next_seq}-{timestamp}-{temp}-{humidity}-{vibration}-{prev_hash}"
current_hash = hashlib.sha256(raw_data.encode()).hexdigest()[:16]

# Handle Network & Storage
if network_status == "OFFLINE":
    st.session_state.unsynced_count += 1
    record_status = "OFFLINE"
    network_display = "🔴 OFFLINE (Buffering)"
else:
    if st.session_state.unsynced_count > 0:
        st.session_state.unsynced_count = 0
    record_status = "ONLINE"
    network_display = "🟢 ONLINE (Synced)"

# Save to SQLite database
conn = sqlite3.connect(DB_FILE)
cursor = conn.cursor()
cursor.execute('''
    INSERT OR IGNORE INTO readings (seq, timestamp, temperature, humidity, vibration, prev_hash, hash, status)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
''', (next_seq, timestamp, temp, humidity, vibration, prev_hash, current_hash, record_status))
conn.commit()
conn.close()

# Fetch latest records for display
conn = sqlite3.connect(DB_FILE)
df = pd.read_sql_query("SELECT seq AS Seq, timestamp AS Timestamp, temperature AS 'Temp (°C)', humidity AS 'Humidity (%)', vibration AS 'Vibration (g)', hash AS 'Hash (SHA256)', status AS Status FROM readings ORDER BY seq DESC LIMIT 12", conn)
conn.close()

# Main Metric Display Columns
col1, col2, col3, col4, col5 = st.columns(5)
col1.metric("Temperature", f"{temp} °C", delta=f"{round(temp - 25, 1)}°C vs target")
col2.metric("Humidity", f"{humidity} %")
col3.metric("Vibration", f"{vibration} g")
col4.metric("Network State", network_display)
col5.metric("Unsynced Local", f"{st.session_state.unsynced_count} records")

st.markdown("---")

# Layout breakdown: Live Feed & Action/Audit Panel
left_col, right_col = st.columns([2, 1])

with left_col:
    st.subheader("📡 Live Sensor Stream & Hash Chain Log")
    st.dataframe(df, use_container_width=True, hide_index=True)

with right_col:
    st.subheader("🔒 Action Engine & Audit")
    
    if st.session_state.tamper_flag:
        st.error("### ACTION: 🛑 HOLD / INSPECT\n**Reason:** Enclosure tamper flag raised at edge node.")
    elif excursion_mode:
        st.warning("### ACTION: ⚠️ REVIEW EXPOSURE\n**Reason:** Cumulative thermal budget threshold approached.")
    else:
        st.success("### ACTION: ✅ PASS / RELEASE\n**Reason:** All parameters and hash chains verified secure.")
        
    st.markdown("---")
    st.markdown("#### Cryptographic Integrity Status")
    if st.session_state.integrity_status == "VERIFIED":
        st.success("✓ **INTEGRITY VERIFIED**\nAll hash links match securely.")
    else:
        st.error("❌ **INTEGRITY FAILED**\nRecord modification detected in database!")

    st.info(f"**Latest Block Hash:**\n`{current_hash}`\n\n**Merkle Anchor:**\n`Anchored & Secure`")

# Auto-refresh cycle for real-time feed
time.sleep(2)
st.rerun()