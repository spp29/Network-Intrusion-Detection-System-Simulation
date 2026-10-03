
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from pathlib import Path
import sqlite3, json, math, statistics
from datetime import datetime, timezone

BASE = Path(__file__).parent
DB = BASE / "ids.db"
app = FastAPI(title="Network IDS Simulation", version="1.0")

def db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    con = db()
    con.execute("""CREATE TABLE IF NOT EXISTS flows(
        flow_id TEXT PRIMARY KEY, timestamp TEXT, source_ip TEXT, destination_ip TEXT,
        source_port INTEGER, destination_port INTEGER, protocol TEXT,
        packet_count INTEGER, byte_count INTEGER, duration_seconds REAL,
        connection_count INTEGER, failed_connection_count INTEGER, syn_count INTEGER,
        rst_count INTEGER, average_packet_size REAL, label TEXT, scenario_type TEXT,
        anomaly_score REAL, risk_score REAL, classification TEXT)""")
    con.execute("""CREATE TABLE IF NOT EXISTS alerts(
        alert_id INTEGER PRIMARY KEY AUTOINCREMENT, flow_id TEXT, timestamp TEXT,
        source_ip TEXT, destination_ip TEXT, protocol TEXT, source_port INTEGER,
        destination_port INTEGER, alert_type TEXT, severity TEXT, risk_score REAL,
        description TEXT, status TEXT DEFAULT 'NEW', notes TEXT DEFAULT '')""")
    con.commit(); con.close()

init_db()

class Flow(BaseModel):
    flow_id: str
    timestamp: str
    source_ip: str
    destination_ip: str
    source_port: int = Field(ge=1, le=65535)
    destination_port: int = Field(ge=1, le=65535)
    protocol: str
    packet_count: int = Field(ge=0)
    byte_count: int = Field(ge=0)
    duration_seconds: float = Field(gt=0)
    connection_count: int = Field(ge=0)
    failed_connection_count: int = Field(ge=0)
    syn_count: int = Field(ge=0)
    rst_count: int = Field(ge=0)
    average_packet_size: float = Field(ge=0)
    label: str = "NORMAL"
    scenario_type: str = "NORMAL_WEB"

def analyze(f):
    pps = f.packet_count / max(f.duration_seconds, .001)
    bps = f.byte_count / max(f.duration_seconds, .001)
    fail_ratio = f.failed_connection_count / max(f.connection_count, 1)
    syn_ratio = f.syn_count / max(f.packet_count, 1)
    hits = []
    if f.connection_count / max(f.duration_seconds, .001) > 25:
        hits.append(("IDS-001","High Connection Rate","HIGH",25))
    if f.failed_connection_count >= 8 or fail_ratio >= .6:
        hits.append(("IDS-002","Repeated Failed Connections","HIGH",25))
    if f.scenario_type == "MULTI_PORT_PROBING_PATTERN" or f.destination_port not in [22,25,53,80,443,3306]:
        if f.connection_count >= 15:
            hits.append(("IDS-003","Unusual Port Activity","MEDIUM",18))
    if syn_ratio >= .65 and f.syn_count >= 25:
        hits.append(("IDS-004","SYN-Heavy Pattern","HIGH",25))
    if bps > 1000000 or f.byte_count > 3000000:
        hits.append(("IDS-005","High Traffic Volume","MEDIUM",18))
    # Lightweight statistical anomaly score based on project baselines.
    deviations = [
        min(100, pps/40*100),
        min(100, bps/1000000*100),
        min(100, fail_ratio*100),
        min(100, syn_ratio*100)
    ]
    anomaly = round(min(100, sum(deviations)/len(deviations)), 1)
    rule_score = min(100, sum(x[3] for x in hits))
    risk = round(min(100, 0.6*rule_score + 0.4*anomaly), 1)
    if risk <= 20: cls="NORMAL"
    elif risk <= 40: cls="LOW RISK"
    elif risk <= 60: cls="SUSPICIOUS"
    elif risk <= 80: cls="HIGH RISK"
    else: cls="CRITICAL INVESTIGATION"
    return hits, anomaly, risk, cls

@app.get("/")
def home():
    return FileResponse(BASE/"static"/"index.html")

@app.post("/api/flows")
def add_flow(flow: Flow):
    hits, anomaly, risk, cls = analyze(flow)
    con=db()
    con.execute("""INSERT OR REPLACE INTO flows VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (flow.flow_id,flow.timestamp,flow.source_ip,flow.destination_ip,flow.source_port,
         flow.destination_port,flow.protocol,flow.packet_count,flow.byte_count,flow.duration_seconds,
         flow.connection_count,flow.failed_connection_count,flow.syn_count,flow.rst_count,
         flow.average_packet_size,flow.label,flow.scenario_type,anomaly,risk,cls))
    for rule_id,typ,sev,_ in hits:
        con.execute("""INSERT INTO alerts(flow_id,timestamp,source_ip,destination_ip,protocol,
            source_port,destination_port,alert_type,severity,risk_score,description)
            VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
            (flow.flow_id,flow.timestamp,flow.source_ip,flow.destination_ip,flow.protocol,
             flow.source_port,flow.destination_port,typ,sev,risk,
             f"{typ} detected from synthetic flow; investigation required."))
    con.commit(); con.close()
    return {"classification":cls,"anomaly_score":anomaly,"risk_score":risk,
            "rules_triggered":[h[1] for h in hits],"alert_created":bool(hits)}

@app.get("/api/alerts")
def alerts():
    con=db()
    rows=[dict(r) for r in con.execute("SELECT * FROM alerts ORDER BY alert_id DESC LIMIT 100")]
    con.close(); return rows

@app.put("/api/alerts/{alert_id}/status")
def status(alert_id:int, body:dict):
    new=body.get("status")
    if new not in ["NEW","INVESTIGATING","RESOLVED","FALSE_POSITIVE"]:
        raise HTTPException(400,"Invalid status")
    con=db(); cur=con.execute("UPDATE alerts SET status=? WHERE alert_id=?",(new,alert_id)); con.commit()
    if cur.rowcount==0: con.close(); raise HTTPException(404,"Alert not found")
    con.close(); return {"ok":True}

@app.post("/api/alerts/{alert_id}/notes")
def notes(alert_id:int, body:dict):
    note=str(body.get("note","")).strip()
    con=db(); cur=con.execute("UPDATE alerts SET notes=? WHERE alert_id=?",(note,alert_id)); con.commit()
    if cur.rowcount==0: con.close(); raise HTTPException(404,"Alert not found")
    con.close(); return {"ok":True}

@app.get("/api/dashboard/stats")
def stats():
    con=db()
    total=con.execute("SELECT COUNT(*) c FROM flows").fetchone()["c"]
    normal=con.execute("SELECT COUNT(*) c FROM flows WHERE classification='NORMAL'").fetchone()["c"]
    suspicious=total-normal
    open_alerts=con.execute("SELECT COUNT(*) c FROM alerts WHERE status IN ('NEW','INVESTIGATING')").fetchone()["c"]
    critical=con.execute("SELECT COUNT(*) c FROM alerts WHERE severity='CRITICAL'").fetchone()["c"]
    avg=con.execute("SELECT COALESCE(AVG(risk_score),0) a FROM flows").fetchone()["a"]
    sev=[dict(r) for r in con.execute("SELECT severity,COUNT(*) count FROM alerts GROUP BY severity")]
    proto=[dict(r) for r in con.execute("SELECT protocol,COUNT(*) count FROM flows GROUP BY protocol")]
    types=[dict(r) for r in con.execute("SELECT alert_type,COUNT(*) count FROM alerts GROUP BY alert_type ORDER BY count DESC")]
    con.close()
    return {"total_flows":total,"normal":normal,"suspicious":suspicious,"open_alerts":open_alerts,
            "critical_alerts":critical,"average_risk":round(avg or 0,1),"severity":sev,"protocols":proto,"types":types}

@app.get("/api/health")
def health(): return {"status":"running","mode":"synthetic-data-only"}
