# Network Intrusion Detection System (IDS) Simulation

A defensive cybersecurity project that simulates network-flow records and detects suspicious patterns without sending real network packets.

## Features
- 5,000 synthetic network-flow records
- Signature/rule-based detection
- Statistical anomaly score (0–100)
- Risk score and classification
- SQLite event/alert storage
- SOC-style dashboard
- Alert status and analyst notes
- Safe replay simulator
- REST API

## Architecture
Synthetic Traffic → Flow Collector/API → Feature Analysis → Rules + Anomaly Detection → Risk Score → Alerts → SQLite → SOC Dashboard

## Safety
All traffic is synthetic. The simulator only creates data records and does not scan, probe, exploit, flood, or attack external systems.

## Run on Windows
1. Install Python 3.10+.
2. Open this folder in VS Code.
3. Open Terminal → New Terminal.
4. Run:
   `python -m venv .venv`
5. Activate:
   `.\.venv\Scripts\activate`
6. Install:
   `pip install -r requirements.txt`
7. Generate data:
   `python generate_dataset.py`
8. Start the server:
   `uvicorn app:app --reload`
9. Open http://127.0.0.1:8000
10. Open a second terminal and run:
   `.\.venv\Scripts\activate`
   `python traffic_simulator.py --speed fast`

## API
- GET /api/health
- POST /api/flows
- GET /api/alerts
- PUT /api/alerts/{id}/status
- POST /api/alerts/{id}/notes
- GET /api/dashboard/stats
- GET /docs

## Limitations
This one-hour MVP uses synthetic flow data and a lightweight statistical anomaly score. A production system could add authorized PCAP/Zeek ingestion, trained ML models, SIEM integration, authentication, and stronger baselines.

## Ethical Disclaimer
This project is designed exclusively for defensive cybersecurity education. All suspicious network behavior is represented using synthetic data or authorized isolated lab environments.
