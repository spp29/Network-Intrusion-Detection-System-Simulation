
import argparse, csv, time, requests
p=argparse.ArgumentParser()
p.add_argument("--speed",choices=["slow","fast"],default="slow")
a=p.parse_args()
delay=.8 if a.speed=="slow" else .15
with open("data/network_traffic.csv",newline="") as f:
    for row in csv.DictReader(f):
        for k in ["source_port","destination_port","packet_count","byte_count","connection_count","failed_connection_count","syn_count","rst_count"]:
            row[k]=int(float(row[k]))
        for k in ["duration_seconds","average_packet_size"]: row[k]=float(row[k])
        r=requests.post("http://127.0.0.1:8000/api/flows",json=row,timeout=5)
        print(r.json())
        time.sleep(delay)
