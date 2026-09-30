import streamlit as st
import pandas as pd
import sqlite3, hashlib, json, random
from datetime import datetime, timezone

st.set_page_config(page_title='FRESHCHAIN POC', page_icon='🔗', layout='wide')
DB='freshchain_poc.db'; DEVICE='FC-EDGE-01'

# ---------------- Database ----------------
def db():
    c=sqlite3.connect(DB, check_same_thread=False)
    c.row_factory=sqlite3.Row
    return c

def init_db():
    c=db(); q=c.cursor()
    q.execute('''CREATE TABLE IF NOT EXISTS telemetry(
        id INTEGER PRIMARY KEY AUTOINCREMENT, shipment_id TEXT, timestamp TEXT,
        seq INTEGER, temperature REAL, humidity REAL, voc REAL, vibration REAL,
        gps_lat REAL, gps_lon REAL, tamper INTEGER, battery REAL, network TEXT,
        prev_hash TEXT, record_hash TEXT, signature TEXT, synced INTEGER DEFAULT 0)''')
    q.execute('''CREATE TABLE IF NOT EXISTS events(
        id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, event_type TEXT,
        description TEXT, seq INTEGER)''')
    q.execute('''CREATE TABLE IF NOT EXISTS anchors(
        id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, seq_from INTEGER,
        seq_to INTEGER, merkle_root TEXT, tx_hash TEXT, status TEXT)''')
    c.commit(); c.close()
init_db()

# ---------------- Helpers ----------------
def now(): return datetime.now(timezone.utc).replace(microsecond=0).isoformat()
def h(s): return hashlib.sha256(str(s).encode()).hexdigest()
def rows_df(rows): return pd.DataFrame([dict(x) for x in rows]) if rows else pd.DataFrame()

def columns(df, wanted, defaults=None):
    defaults=defaults or {}
    for x in wanted:
        if x not in df.columns: df[x]=defaults.get(x,'')
    return df[wanted]

def next_seq():
    c=db(); n=c.execute('SELECT COALESCE(MAX(seq),0) n FROM telemetry').fetchone()['n']; c.close(); return n+1

def prev_hash():
    c=db(); r=c.execute('SELECT record_hash FROM telemetry ORDER BY seq DESC LIMIT 1').fetchone(); c.close()
    return r['record_hash'] if r else '0'*64

def event(kind,desc,seq=None):
    c=db(); c.execute('INSERT INTO events(timestamp,event_type,description,seq) VALUES(?,?,?,?)',(now(),kind,desc,seq)); c.commit(); c.close()

def merkle(vals):
    if not vals: return ''
    a=list(vals)
    while len(a)>1:
        if len(a)%2: a.append(a[-1])
        a=[h(a[i]+a[i+1]) for i in range(0,len(a),2)]
    return a[0]

# ---------------- State ----------------
if 'shipment' not in st.session_state: st.session_state.shipment='FC-1042'
if 'online' not in st.session_state: st.session_state.online=True
if 'temp' not in st.session_state: st.session_state.temp=6.0
if 'battery' not in st.session_state: st.session_state.battery=84.0

# ---------------- Record generation ----------------
def add_record(tamper=0):
    seq=next_seq(); p=prev_hash(); ts=now(); online=st.session_state.online
    temp=round(st.session_state.temp+random.uniform(-.25,.25),2)
    rh=round(random.uniform(72,84),2); voc=round(random.uniform(180,280),2)
    vib=round(random.uniform(.01,.15),3); bat=round(max(5,st.session_state.battery-random.uniform(.01,.08)),2)
    lat=round(11.0168+random.uniform(-.001,.001),6); lon=round(76.9558+random.uniform(-.001,.001),6)
    payload={'device':DEVICE,'shipment':st.session_state.shipment,'seq':seq,'timestamp':ts,
             'temperature':temp,'humidity':rh,'voc':voc,'vibration':vib,'lat':lat,'lon':lon,
             'tamper':tamper,'battery':bat,'network':'ONLINE' if online else 'OFFLINE','prev':p}
    rhash=h(json.dumps(payload,sort_keys=True)+p)
    # POC signature representation; hardware target is ATECC608B ECDSA.
    sig=h('ATECC608B-P0C|'+DEVICE+'|'+rhash)
    c=db(); c.execute('''INSERT INTO telemetry
      (shipment_id,timestamp,seq,temperature,humidity,voc,vibration,gps_lat,gps_lon,tamper,battery,network,prev_hash,record_hash,signature,synced)
      VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
      (st.session_state.shipment,ts,seq,temp,rh,voc,vib,lat,lon,tamper,bat,
       'ONLINE' if online else 'OFFLINE',p,rhash,sig,1 if online else 0))
    c.commit(); c.close(); st.session_state.battery=bat
    if tamper: event('TAMPER','Enclosure-open event recorded.',seq)
    return seq

# ---------------- Integrity ----------------
def verify():
    c=db(); rs=c.execute('SELECT * FROM telemetry ORDER BY seq').fetchall(); c.close()
    if not rs: return {'valid':True,'verified':0,'modified':0,'gaps':0}
    prev='0'*64; expected=rs[0]['seq']; bad=0; gaps=0
    for r in rs:
        if r['seq']!=expected: gaps+=max(0,r['seq']-expected)
        payload={'device':DEVICE,'shipment':r['shipment_id'],'seq':r['seq'],'timestamp':r['timestamp'],
          'temperature':r['temperature'],'humidity':r['humidity'],'voc':r['voc'],'vibration':r['vibration'],
          'lat':r['gps_lat'],'lon':r['gps_lon'],'tamper':r['tamper'],'battery':r['battery'],
          'network':r['network'],'prev':prev}
        if h(json.dumps(payload,sort_keys=True)+prev)!=r['record_hash']: bad+=1
        prev=r['record_hash']; expected=r['seq']+1
    return {'valid':bad==0 and gaps==0,'verified':len(rs)-bad,'modified':bad,'gaps':gaps}

# ---------------- Condition model ----------------
def condition():
    c=db(); rs=c.execute('SELECT temperature,humidity,vibration,tamper FROM telemetry ORDER BY seq').fetchall(); c.close()
    exposure=0
    for r in rs:
        exposure += max(0,r['temperature']-8)*1.8
        exposure += max(0,70-r['humidity'])*.08 + max(0,r['humidity']-85)*.08
        exposure += r['vibration']*.4 + (5 if r['tamper'] else 0)
    budget=round(min(100,exposure),1)
    if budget>=70: p='Very High'
    elif budget>=40: p='High'
    else: p='Normal'
    return budget,p

# ---------------- UI ----------------
st.sidebar.title('FRESHCHAIN POC')
st.session_state.shipment=st.sidebar.text_input('Shipment ID',st.session_state.shipment)
st.session_state.temp=st.sidebar.slider('Simulated temperature (°C)',0.0,40.0,st.session_state.temp,.5)
if st.sidebar.button('Generate Sensor Record',use_container_width=True): add_record(); st.rerun()
if st.sidebar.button('Generate 10 Records',use_container_width=True):
    for _ in range(10): add_record()
    st.rerun()
if st.sidebar.button('Trigger Tamper Event',use_container_width=True): add_record(1); st.rerun()
if st.sidebar.button('Reset POC Database',use_container_width=True):
    c=db(); c.execute('DELETE FROM telemetry'); c.execute('DELETE FROM events'); c.execute('DELETE FROM anchors'); c.commit(); c.close(); st.rerun()

st.title('FRESHCHAIN')
st.caption('Low-Cost IoT Blockchain Node for Farm-to-Fork Traceability')

c=db(); total=c.execute('SELECT COUNT(*) n FROM telemetry').fetchone()['n']; off=c.execute("SELECT COUNT(*) n FROM telemetry WHERE network='OFFLINE'").fetchone()['n']; tam=c.execute("SELECT COUNT(*) n FROM events WHERE event_type='TAMPER'").fetchone()['n']; anchors=c.execute('SELECT COUNT(*) n FROM anchors').fetchone()['n']; c.close()
a,b,c,d=st.columns(4); a.metric('Records',total); b.metric('Offline Records',off); c.metric('Tamper Events',tam); d.metric('Blockchain Anchors',anchors)

st.subheader('Connectivity')
x,y=st.columns([1,3])
with x: st.success('ONLINE') if st.session_state.online else st.error('OFFLINE')
with y:
    if st.button('Disconnect Network' if st.session_state.online else 'Restore Network',use_container_width=True):
        st.session_state.online=not st.session_state.online
        if st.session_state.online:
            c=db(); c.execute("UPDATE telemetry SET synced=1 WHERE network='OFFLINE'"); c.commit(); c.close(); event('SYNC','Offline records synchronized after network restoration.')
        else: event('NETWORK','Network disconnected. Offline logging enabled.')
        st.rerun()

budget,priority=condition(); q1,q2,q3=st.columns(3); q1.metric('Shelf-Life Budget Used',f'{budget}%'); q2.metric('Priority',priority); q3.metric('Battery',f"{st.session_state.battery:.1f}%")

# ---------------- Tabs ----------------
t1,t2,t3,t4=st.tabs(['Shipment Overview','Journey Timeline','Integrity Verification','Action View'])
with t1:
    st.subheader('Latest Sensor Data'); c=db(); rs=c.execute('''SELECT timestamp,seq,temperature,humidity,voc,vibration,battery,network,tamper FROM telemetry ORDER BY seq DESC LIMIT 25''').fetchall(); c.close(); df=rows_df(rs)
    wanted=['timestamp','seq','temperature','humidity','voc','vibration','battery','network','tamper']
    if df.empty: st.info('No telemetry records yet.')
    else: st.dataframe(columns(df,wanted),use_container_width=True,hide_index=True)

with t2:
    st.subheader('Journey Timeline'); c=db(); rs=c.execute('SELECT timestamp,event_type,description,seq FROM events ORDER BY id DESC LIMIT 100').fetchall(); c.close(); edf=rows_df(rs)
    wanted=['timestamp','event_type','description','seq']
    if edf.empty: st.info('No journey events recorded.')
    else: st.dataframe(columns(edf,wanted),use_container_width=True,hide_index=True)
    c=db(); rs=c.execute('SELECT timestamp,temperature,humidity FROM telemetry ORDER BY seq').fetchall(); c.close(); chart=rows_df(rs)
    if not chart.empty:
        chart['timestamp']=pd.to_datetime(chart['timestamp'],errors='coerce'); chart=chart.set_index('timestamp'); st.line_chart(chart[['temperature','humidity']])

with t3:
    st.subheader('Integrity Verification'); vr=verify(); a,b,c,d=st.columns(4); a.metric('Verified',vr['verified']); b.metric('Modified',vr['modified']); c.metric('Sequence Gaps',vr['gaps']); d.metric('Status','PASS' if vr['valid'] else 'FAIL')
    st.success('✓ Integrity verification passed.') if vr['valid'] else st.error('✗ Integrity verification failed.')
    st.subheader('Blockchain Anchors')
    c=db(); rs=c.execute('SELECT timestamp,seq_from,seq_to,merkle_root,tx_hash,status FROM anchors ORDER BY id DESC').fetchall(); c.close(); adf=rows_df(rs)
    # FIX for the reported KeyError: always create missing display columns first.
    wanted=['timestamp','seq_from','seq_to','merkle_root','tx_hash','status']
    if adf.empty: st.info('No blockchain anchor created yet.')
    else: st.dataframe(columns(adf,wanted),use_container_width=True,hide_index=True)
    if st.button('Create Blockchain Anchor'):
        c=db(); rs=c.execute('SELECT seq,record_hash FROM telemetry WHERE synced=1 ORDER BY seq').fetchall(); c.close()
        if rs:
            root=merkle([r['record_hash'] for r in rs]); tx='0x'+h('EVM_TESTNET|'+root)
            c=db(); c.execute('INSERT INTO anchors(timestamp,seq_from,seq_to,merkle_root,tx_hash,status) VALUES(?,?,?,?,?,?)',(now(),rs[0]['seq'],rs[-1]['seq'],root,tx,'ANCHORED')); c.commit(); c.close(); st.success('Merkle root anchored on the POC testnet representation.'); st.rerun()
        else: st.warning('No telemetry available.')

with t4:
    st.subheader('Condition-Aware Action Engine'); vr=verify()
    action='INSPECT / HOLD' if tam>0 or not vr['valid'] else ('VERY HIGH PRIORITY' if priority=='Very High' else 'HIGH PRIORITY' if priority=='High' else 'NORMAL')
    reason='Tamper event or integrity verification failure detected.' if tam>0 or not vr['valid'] else ('High cumulative environmental exposure.' if priority!='Normal' else 'Condition currently within normal range.')
    st.metric('Recommended Handling',action); st.write('**Reason:**',reason)
    st.dataframe(pd.DataFrame([{'Shipment':st.session_state.shipment,'Condition Budget Used':f'{budget}%','Priority':action,'Reason':reason}]),use_container_width=True,hide_index=True)

st.divider(); st.write('**FRESHCHAIN Pipeline:** Sense → Sign → Store → Survive → Sync → Prove → Assess → Act')
st.caption('POC: simulated sensing, offline buffering, SHA-256 hash chain, signing representation, Merkle anchoring, integrity verification and condition-aware action.')
