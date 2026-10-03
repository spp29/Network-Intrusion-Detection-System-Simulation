
import csv, random, uuid
from pathlib import Path
from datetime import datetime, timedelta, timezone

OUT=Path(__file__).parent/"data"/"network_traffic.csv"
OUT.parent.mkdir(exist_ok=True)
reserved_src=["192.0.2.15","192.0.2.20","192.0.2.30","192.0.2.40"]
reserved_dst=["198.51.100.20","198.51.100.30","203.0.113.10"]
normal=[("NORMAL_WEB",443,"TCP"),("NORMAL_DNS",53,"UDP"),("NORMAL_SSH",22,"TCP"),
        ("NORMAL_EMAIL",25,"TCP"),("NORMAL_DATABASE",3306,"TCP")]
susp=[("HIGH_CONNECTION_RATE",443,"TCP"),("REPEATED_FAILED_CONNECTIONS",22,"TCP"),
      ("MULTI_PORT_PROBING_PATTERN",random.randint(1000,5000),"TCP"),
      ("SYN_HEAVY_PATTERN",443,"TCP"),("HIGH_TRAFFIC_VOLUME",443,"TCP")]
rows=[]; now=datetime.now(timezone.utc)
for i in range(5000):
    suspicious=i>=4200
    scen=random.choice(susp if suspicious else normal)
    st,dp,proto=scen
    if st=="HIGH_CONNECTION_RATE":
        conn=random.randint(40,90); dur=random.uniform(.5,2)
        failed=random.randint(0,4); syn=random.randint(20,40); packets=random.randint(80,180); bytes_=packets*random.randint(500,1200)
    elif st=="REPEATED_FAILED_CONNECTIONS":
        conn=random.randint(10,30); dur=random.uniform(2,6); failed=random.randint(8,20); syn=random.randint(5,20); packets=random.randint(30,90); bytes_=packets*400
    elif st=="MULTI_PORT_PROBING_PATTERN":
        conn=random.randint(20,45); dur=random.uniform(1,4); failed=random.randint(5,15); syn=random.randint(15,50); packets=random.randint(40,120); bytes_=packets*150
    elif st=="SYN_HEAVY_PATTERN":
        conn=random.randint(10,30); dur=random.uniform(1,3); failed=random.randint(3,10); packets=random.randint(60,150); syn=int(packets*.75); bytes_=packets*200
    elif st=="HIGH_TRAFFIC_VOLUME":
        conn=random.randint(2,10); dur=random.uniform(1,5); failed=random.randint(0,2); syn=random.randint(1,8); packets=random.randint(2000,5000); bytes_=random.randint(3000000,7000000)
    else:
        conn=random.randint(1,6); dur=random.uniform(1,12); failed=random.randint(0,1); packets=random.randint(10,80); syn=random.randint(1,8); bytes_=random.randint(1000,80000)
    ts=(now-timedelta(seconds=random.randint(0,86400))).isoformat()
    src=random.choice(reserved_src); dst=random.choice(reserved_dst)
    avg=bytes_/max(packets,1)
    rows.append([f"FLOW-{i+1:05d}",ts,src,dst,random.randint(1024,65000),dp,proto,packets,bytes_,round(dur,3),conn,failed,syn,random.randint(0,5),round(avg,2),"SUSPICIOUS" if suspicious else "NORMAL",st])
cols=["flow_id","timestamp","source_ip","destination_ip","source_port","destination_port","protocol","packet_count","byte_count","duration_seconds","connection_count","failed_connection_count","syn_count","rst_count","average_packet_size","label","scenario_type"]
with open(OUT,"w",newline="") as f:
    w=csv.writer(f); w.writerow(cols); w.writerows(rows)
print(f"Created {len(rows)} synthetic flow records: {OUT}")
