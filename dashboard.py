import streamlit as st
import sqlite3, hashlib, json, time, math, os
from datetime import datetime, timedelta
from pathlib import Path

try:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    CRYPTO_OK = True
except Exception:
    CRYPTO_OK = False

DB = Path("freshchain.db")
DEVICE_ID = "FC-NODE-01"
MQTT_TOPIC = "freshchain/FC-NODE-01/telemetry"

st.set_page_config(page_title="FRESHCHAIN", page_icon=None, layout="wide", initial_sidebar_state="expanded")

# ---------- Human-made engineering-console styling ----------
st.markdown("""
<style>
html, body, [class*="css"] { font-family: "Segoe UI", Arial, sans-serif; }
.block-container { padding-top: 1.6rem; padding-bottom: 2rem; max-width: 1450px; }
h1 { font-size: 30px !important; font-weight: 600 !important; letter-spacing: -0.2px; }
h2 { font-size: 21px !important; font-weight: 600 !important; }
h3 { font-size: 16px !important; font-weight: 600 !important; }
p, label, .stMarkdown, .stText { font-size: 14px; }
.small { font-size: 12px; color: #666; }
.rule { border-top: 1px solid #d7d7d7; margin: 12px 0 18px 0; }
.panel {
    border: 1px solid #cfcfcf; background: #fff; padding: 14px 16px;
    border-radius: 3px; margin-bottom: 12px;
}
.metric-label { font-size: 12px; color: #666; margin-bottom: 3px; }
.metric-value { font-size: 22px; font-weight: 600; }
.ok { color: #176b35; font-weight: 600; }
.warn { color: #a55a00; font-weight: 600; }
.danger { color: #b42318; font-weight: 600; }
.info { color: #245b8f; font-weight: 600; }
.badge {
    display: inline-block; padding: 3px 8px; border-radius: 2px;
    border: 1px solid #bbb; font-size: 12px; margin-right: 5px;
}
.badge-ok { color:#176b35; border-color:#8bb79b; background:#f4faf6; }
.badge-warn { color:#9a5b00; border-color:#d8b77d; background:#fffaf0; }
.badge-red { color:#b42318; border-color:#e1a29d; background:#fff6f5; }
.badge-grey { color:#555; background:#f5f5f5; }
div[data-testid="stMetric"] {
    border: 1px solid #d2d2d2; padding: 9px 12px; border-radius: 3px;
    background: #fff;
}
button[kind="primary"] { border-radius: 3px !important; }
.stTabs [data-baseweb="tab-list"] { gap: 0; border-bottom: 1px solid #cfcfcf; }
.stTabs [data-baseweb="tab"] { padding: 8px 18px; }
footer { visibility: hidden; }
</style>
""", unsafe_allow_html=True)

# ---------- Database ----------
def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c

def init_db():
    c = db()
    c.execute("""CREATE TABLE IF NOT EXISTS readings(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        seq INTEGER UNIQUE,
        timestamp TEXT,
        temperature REAL,
        humidity REAL,
        voc REAL,
        vibration REAL,
        latitude REAL,
        longitude REAL,
        battery REAL,
        tamper INTEGER DEFAULT 0,
        network INTEGER DEFAULT 1,
        prev_hash TEXT,
        hash TEXT,
        signature TEXT,
        encrypted_payload TEXT,
        synced INTEGER DEFAULT 0
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS events(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT, event TEXT, severity TEXT, detail TEXT
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS anchors(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT, seq_from INTEGER, seq_to INTEGER,
        merkle_root TEXT, chain_hash TEXT, tx_hash TEXT, status TEXT
    )""")
    c.commit(); c.close()

init_db()

# ---------- Crypto / trust layer ----------
def sha256(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()

def canonical_record(seq, ts, temp, rh, voc, vib, lat, lon, batt, tamper, network):
    return json.dumps({
        "device_id": DEVICE_ID, "seq": seq, "timestamp": ts,
        "temperature": round(temp, 2), "humidity": round(rh, 2),
        "voc": round(voc, 2), "vibration": round(vib, 3),
        "latitude": round(lat, 5), "longitude": round(lon, 5),
        "battery": round(batt, 2), "tamper": int(tamper), "network": int(network)
    }, sort_keys=True, separators=(",", ":"))

def get_or_make_keys():
    if not CRYPTO_OK:
        return None, None
    if "private_key" not in st.session_state:
        st.session_state.private_key = ec.generate_private_key(ec.SECP256R1())
    prv = st.session_state.private_key
    pub = prv.public_key()
    return prv, pub

def sign_text(text):
    prv, _ = get_or_make_keys()
    if not prv: return "CRYPTO_UNAVAILABLE"
    sig = prv.sign(text.encode(), ec.ECDSA(hashes.SHA256()))
    return sig.hex()

def verify_signature(text, sig_hex):
    _, pub = get_or_make_keys()
    if not pub or sig_hex == "CRYPTO_UNAVAILABLE": return False
    try:
        pub.verify(bytes.fromhex(sig_hex), text.encode(), ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False

def encrypt_text(text):
    if not CRYPTO_OK: return "AES_GCM_UNAVAILABLE"
    if "aes_key" not in st.session_state:
        st.session_state.aes_key = AESGCM.generate_key(bit_length=256)
    aes = AESGCM(st.session_state.aes_key)
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, text.encode(), DEVICE_ID.encode())
    return (nonce + ct).hex()

# ---------- Merkle ----------
def merkle_root(items):
    if not items: return ""
    layer = [bytes.fromhex(x) for x in items]
    while len(layer) > 1:
        if len(layer) % 2: layer.append(layer[-1])
        layer = [hashlib.sha256(layer[i] + layer[i+1]).digest() for i in range(0, len(layer), 2)]
    return layer[0].hex()

def latest_rows(limit=500):
    c = db(); rows = c.execute("SELECT * FROM readings ORDER BY seq DESC LIMIT ?", (limit,)).fetchall()
    c.close(); return list(reversed(rows))

def add_event(event, severity="INFO", detail=""):
    c=db(); c.execute("INSERT INTO events(timestamp,event,severity,detail) VALUES(?,?,?,?)",
                      (datetime.now().isoformat(timespec="seconds"),event,severity,detail))
    c.commit(); c.close()

def log_reading(network=True, force_excursion=False, force_tamper=False):
    rows = latest_rows(1)
    seq = (rows[-1]["seq"] + 1) if rows else 1
    prev = rows[-1]["hash"] if rows else "0"*64
    if force_excursion:
        temp = 30.5 + (seq % 5) * 0.55
    else:
        temp = 24.2 + ((seq * 17) % 31) / 10
    rh = 67 + ((seq * 7) % 70) / 10
    voc = 0.20 + ((seq * 13) % 70) / 100
    vib = 0.04 + ((seq * 11) % 30) / 100
    lat = 11.0168 + ((seq % 20) / 10000)
    lon = 76.9558 + ((seq % 25) / 10000)
    batt = max(12.0, 96.0 - seq * 0.07)
    tamper = int(force_tamper)
    ts = datetime.now().isoformat(timespec="seconds")
    raw = canonical_record(seq, ts, temp, rh, voc, vib, lat, lon, batt, tamper, network)
    h = sha256(raw + prev)
    sig = sign_text(h)
    enc = encrypt_text(raw)
    c=db()
    c.execute("""INSERT INTO readings(seq,timestamp,temperature,humidity,voc,vibration,latitude,longitude,
                 battery,tamper,network,prev_hash,hash,signature,encrypted_payload,synced)
                 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
              (seq,ts,temp,rh,voc,vib,lat,lon,batt,tamper,int(network),prev,h,sig,enc,int(network)))
    c.commit(); c.close()
    if tamper: add_event("Enclosure tamper", "HIGH", "Open/backup-rail switch event recorded.")
    if not network: add_event("Network outage", "WARNING", "Logging continued locally; record marked unsynced.")
    if temp >= 28: add_event("Temperature excursion", "WARNING", f"{temp:.1f} °C recorded.")
    return seq

def verify_chain():
    rows=latest_rows(5000)
    if not rows: return {"records":0,"verified":0,"modified":0,"gaps":0,"bad_seq":[],"bad_hash":[],"bad_sig":[]}
    bad_hash=[]; bad_sig=[]; bad_seq=[]
    expected=rows[0]["seq"]
    prev="0"*64
    for r in rows:
        if r["seq"] != expected: bad_seq.append((expected,r["seq"]))
        raw=canonical_record(r["seq"],r["timestamp"],r["temperature"],r["humidity"],r["voc"],r["vibration"],
                             r["latitude"],r["longitude"],r["battery"],r["tamper"],r["network"])
        calc=sha256(raw + prev)
        if calc != r["hash"]: bad_hash.append(r["seq"])
        if not verify_signature(r["hash"], r["signature"]): bad_sig.append(r["seq"])
        prev=r["hash"]; expected=r["seq"]+1
    modified=sorted(set(bad_hash+bad_sig))
    return {"records":len(rows),"verified":len(rows)-len(modified),"modified":len(modified),
            "gaps":len(bad_seq),"bad_seq":bad_seq,"bad_hash":bad_hash,"bad_sig":bad_sig}

def anchor_latest_batch():
    rows=latest_rows(5000)
    if not rows: return None
    root=merkle_root([r["hash"] for r in rows])
    chain=rows[-1]["hash"]
    tx="0x"+sha256(root + DEVICE_ID + str(rows[0]["seq"]) + str(rows[-1]["seq"]))[:64]
    c=db()
    c.execute("""INSERT INTO anchors(timestamp,seq_from,seq_to,merkle_root,chain_hash,tx_hash,status)
                 VALUES(?,?,?,?,?,?,?)""",
              (datetime.now().isoformat(timespec="seconds"),rows[0]["seq"],rows[-1]["seq"],root,chain,tx,"LOCAL EVM DEMO ANCHOR"))
    c.commit(); c.close()
    return root, tx

def exposure():
    rows=latest_rows(5000)
    if not rows: return 0.0, []
    budget=100.0
    consumed=0.0; drivers=[]
    for r in rows:
        t=r["temperature"]
        # POC parameterization for mango; not lab calibrated.
        rate=2 ** ((t-25.0)/10.0)
        consumed += rate * 0.35
        if t >= 29: drivers.append(f"{t:.1f} °C excursion")
        if r["humidity"] > 80 or r["humidity"] < 55: drivers.append("Humidity outside reference band")
        if r["vibration"] > 0.25: drivers.append("Shock/vibration")
    pct=min(100, consumed/budget*100)
    return pct, drivers[-4:]

def condition_decision():
    pct, drivers=exposure()
    v=verify_chain()
    rows=latest_rows(5000)
    tamper=any(r["tamper"] for r in rows)
    if v["modified"] or v["gaps"] or tamper:
        return "INSPECT / HOLD", "danger", pct, ["Integrity/tamper event requires inspection."]
    if pct >= 70: return "VERY HIGH", "danger", pct, drivers or ["High cumulative exposure"]
    if pct >= 40: return "HIGH", "warn", pct, drivers or ["Elevated cumulative exposure"]
    return "NORMAL", "ok", pct, drivers or ["No major condition driver"]

# ---------- Sidebar ----------
with st.sidebar:
    st.markdown("### FRESHCHAIN")
    st.caption("Farm-to-fork traceability console")
    st.markdown('<div class="rule"></div>', unsafe_allow_html=True)
    st.markdown("**Node**")
    st.code(DEVICE_ID, language=None)
    st.markdown("**Controls**")
    network = st.toggle("Network available", value=True)
    excursion = st.toggle("Temperature excursion", value=False)
    tamper = st.toggle("Tamper event", value=False)
    interval = st.slider("Records per run", 1, 10, 1)
    if st.button("Record sensor data", use_container_width=True):
        for _ in range(interval):
            log_reading(network, excursion, tamper)
        st.rerun()
    if st.button("Reset local POC database", use_container_width=True):
        c=db()
        c.execute("DELETE FROM readings"); c.execute("DELETE FROM events"); c.execute("DELETE FROM anchors")
        c.commit(); c.close()
        st.rerun()
    st.markdown('<div class="rule"></div>', unsafe_allow_html=True)
    st.markdown("**Implementation status**")
    st.markdown("`LIVE IN LAPTOP POC`")
    st.caption("ESP32-S3, ATECC608B, LTE and physical sensors are represented by software equivalents here.")
    st.caption("MQTT can be enabled from the MQTT module when a broker is available.")

# ---------- Header ----------
st.markdown("# FRESHCHAIN")
st.markdown("**Low-cost IoT node for farm-to-fork traceability**")
st.caption("Sense  >  Sign  >  Store  >  Survive  >  Sync  >  Prove  >  Assess  >  Act")
st.markdown('<div class="rule"></div>', unsafe_allow_html=True)

rows=latest_rows()
v=verify_chain()
decision, cls, pct, drivers = condition_decision()
last=rows[-1] if rows else None
offline_count=sum(1 for r in rows if not r["synced"])
anchor_rows=db().execute("SELECT * FROM anchors ORDER BY id DESC LIMIT 1").fetchall() if False else []

# top status line
net_text = "ONLINE" if network else "OFFLINE"
net_cls = "ok" if network else "danger"
tamper_text = "TAMPER DETECTED" if (last and last["tamper"]) else "TAMPER CLEAR"
tamper_cls = "danger" if (last and last["tamper"]) else "ok"
st.markdown(
    f'<span class="badge badge-{"ok" if network else "red"}">{net_text}</span>'
    f'<span class="badge badge-{"red" if (last and last["tamper"]) else "ok"}">{tamper_text}</span>'
    f'<span class="badge badge-grey">SIMULATION / LAPTOP POC</span>',
    unsafe_allow_html=True)

tabs=st.tabs(["Overview","Journey","Integrity","Action View"])

# ---------- Overview ----------
with tabs[0]:
    st.markdown("## Shipment overview")
    if not last:
        st.info("No records yet. Use the controls on the left and select Record sensor data.")
    else:
        cols=st.columns(6)
        vals=[
            ("Temperature",f'{last["temperature"]:.1f} °C'),
            ("Humidity",f'{last["humidity"]:.1f} %'),
            ("VOC trend",f'{last["voc"]:.2f}'),
            ("Vibration",f'{last["vibration"]:.2f} g'),
            ("Battery",f'{last["battery"]:.0f} %'),
            ("Records",str(len(rows)))
        ]
        for col,(lab,val) in zip(cols,vals):
            with col:
                st.markdown(f'<div class="metric-label">{lab}</div><div class="metric-value">{val}</div>',unsafe_allow_html=True)
        st.markdown("")
        c1,c2=st.columns([1.2,1])
        with c1:
            st.markdown("### Condition")
            st.markdown(f'<div class="{cls}" style="font-size:24px">{decision}</div>',unsafe_allow_html=True)
            st.write(f"Estimated exposure budget consumed: **{pct:.1f}%**")
            st.progress(min(1,pct/100))
            st.caption("POC model: cumulative thermal exposure with humidity/shock flags. Literature-parameterized, not experimentally calibrated.")
            if drivers:
                st.write("Drivers:")
                for d in drivers: st.write(f"- {d}")
        with c2:
            st.markdown("### Node state")
            st.write(f"Connectivity: **{net_text}**")
            st.write(f"Local unsynced records: **{offline_count}**")
            st.write(f"Last timestamp: **{last['timestamp']}**")
            st.write(f"GPS: **{last['latitude']:.5f}, {last['longitude']:.5f}**")
            st.write(f"Tamper input: **{'TRIGGERED' if last['tamper'] else 'CLEAR'}**")
            st.write(f"Encryption: **AES-256-GCM equivalent active**" if CRYPTO_OK else "Encryption: unavailable")
    st.markdown("### Recent telemetry")
if rows:
    import pandas as pd
    df = pd.DataFrame([dict(r) for r in rows])[[
        "seq", "timestamp", "temperature", "humidity",
        "voc", "vibration", "battery", "network",
        "synced", "tamper"
    ]]
    st.dataframe(df.tail(15), use_container_width=True, hide_index=True)
else:
    st.caption("Waiting for the first record.")

# ---------- Journey ----------
with tabs[1]:
    st.markdown("## Journey timeline")
    if rows:
        import pandas as pd
        df = pd.DataFrame([dict(r) for r in rows])

        chart = df[["seq", "temperature", "humidity"]].set_index("seq")
        st.line_chart(chart, height=300)

        st.markdown("### Events")
        c = db()
        ev = c.execute(
            "SELECT * FROM events ORDER BY id DESC LIMIT 30"
        ).fetchall()
        c.close()

        if ev:
            evdf = pd.DataFrame([dict(r) for r in ev])
            st.dataframe(
                evdf[["timestamp", "event", "severity", "detail"]],
                use_container_width=True,
                hide_index=True
            )
        else:
            st.caption("No events recorded.")

        st.markdown("### Position trace")
        map_df = df[["latitude", "longitude"]].rename(
            columns={"latitude": "lat", "longitude": "lon"}
        )
        st.map(map_df)

    else:
        st.info("Record data to build the journey.")

# ---------- Integrity ----------
with tabs[2]:
    st.markdown("## Integrity verification")
    st.caption("The laptop POC implements the same trust sequence as the proposed node: record → hash chain → signature → encrypted payload → Merkle root → anchor.")
    cols=st.columns(5)
    items=[("Records",v["records"]),("Verified",v["verified"]),("Modified",v["modified"]),("Sequence gaps",v["gaps"]),("Crypto","ECDSA + AES-GCM" if CRYPTO_OK else "Unavailable")]
    for col,(lab,val) in zip(cols,items):
        with col: st.metric(lab,val)
    if st.button("VERIFY INTEGRITY", type="primary"):
        v=verify_chain()
        if v["modified"]==0 and v["gaps"]==0:
            st.success(f"Verification passed: {v['records']} records checked.")
        else:
            st.error(f"Verification failed. Modified records: {v['modified']}; sequence gaps: {v['gaps']}.")
            if v["bad_hash"]: st.write("Hash mismatch:",v["bad_hash"])
            if v["bad_sig"]: st.write("Signature mismatch:",v["bad_sig"])
            if v["bad_seq"]: st.write("Sequence gaps:",v["bad_seq"])
    st.markdown("### Merkle / blockchain anchor")
    if st.button("Create local Merkle anchor"):
        out=anchor_latest_batch()
        if out: st.success("Merkle root created and stored as a local EVM-style demo anchor.")
    c=db(); a=c.execute("SELECT * FROM anchors ORDER BY id DESC LIMIT 3").fetchall(); c.close()
    if a:
        import pandas as pd
        adf=pd.DataFrame(a)
        st.dataframe(adf[["timestamp","seq_from","seq_to","merkle_root","tx_hash","status"]],use_container_width=True,hide_index=True)
    st.caption("For the final hardware build, the signing operation maps to ATECC608B and the anchor can be submitted to a real EVM testnet using the supplied Solidity contract. This laptop POC does not pretend a local hash is a public blockchain transaction.")
    st.markdown("### Demonstration: detect database tampering")
    if st.button("Inject database modification"):
        c=db(); r=c.execute("SELECT id FROM readings ORDER BY seq DESC LIMIT 1").fetchone()
        if r:
            c.execute("UPDATE readings SET temperature=temperature+8.0 WHERE id=?",(r["id"],))
            c.commit()
            add_event("Database modification injected","HIGH","Latest temperature changed deliberately for verification demo.")
        c.close()
        st.rerun()

# ---------- Action view ----------
with tabs[3]:
    st.markdown("## Action view")
    st.caption("Decision support for handling priority. It is not an autonomous food-safety authority.")
    import pandas as pd
    samples=[
        {"Shipment":"FC-1042","Commodity":"Mango","Budget consumed":"38%","Transit remaining":"18 h","Priority":"Normal","Reason":"Stable exposure"},
        {"Shipment":"FC-1047","Commodity":"Mango","Budget consumed":"61%","Transit remaining":"10 h","Priority":"High","Reason":"Thermal exposure"},
        {"Shipment":"FC-1051","Commodity":"Mango","Budget consumed":"82%","Transit remaining":"7 h","Priority":"Very High","Reason":"Extended temperature excursion"},
    ]
    current={"Shipment":"FC-NODE-01","Commodity":"Mango","Budget consumed":f"{pct:.0f}%","Transit remaining":"POC","Priority":decision,
             "Reason":"; ".join(drivers)}
    data=pd.DataFrame([current]+samples)
    def mark_priority(x):
        if "HOLD" in str(x): return "background-color:#fff0ef;color:#b42318;font-weight:600"
        if "VERY HIGH" in str(x): return "background-color:#fff0ef;color:#b42318;font-weight:600"
        if "HIGH" in str(x): return "background-color:#fff8e8;color:#9a5b00;font-weight:600"
        return ""
    st.dataframe(data.style.map(mark_priority, subset=["Priority"]),use_container_width=True,hide_index=True)
    st.markdown("### Current handling logic")
    st.write("- Integrity failure or tamper event → **INSPECT / HOLD**, regardless of exposure score.")
    st.write("- Exposure budget + remaining transit → Normal / High / Very High.")
    st.write("- VOC is shown as a ripening-trend flag and is not folded into the score until validated.")
    st.write("- FEFO-style ordering is decision support for earlier processing/distribution/inspection.")

st.markdown('<div class="rule"></div>', unsafe_allow_html=True)
st.caption("FRESHCHAIN | SIH PS 26232 | Laptop proof-of-concept. Physical sensors, ATECC608B, LTE, solar/PMIC and rugged enclosure are hardware targets; their software equivalents are demonstrated here.")
