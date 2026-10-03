import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import analyze, Flow


def test_normal():
    f = Flow(
        flow_id="T1",
        timestamp="2026-01-01T00:00:00Z",
        source_ip="192.0.2.1",
        destination_ip="198.51.100.1",
        source_port=50000,
        destination_port=443,
        protocol="TCP",
        packet_count=30,
        byte_count=20000,
        duration_seconds=5,
        connection_count=2,
        failed_connection_count=0,
        syn_count=3,
        rst_count=0,
        average_packet_size=666
    )

    hits, anomaly, risk, classification = analyze(f)

    assert classification == "NORMAL"
    assert not hits


def test_high_connections():
    f = Flow(
        flow_id="T2",
        timestamp="2026-01-01T00:00:00Z",
        source_ip="192.0.2.1",
        destination_ip="198.51.100.1",
        source_port=50000,
        destination_port=443,
        protocol="TCP",
        packet_count=100,
        byte_count=50000,
        duration_seconds=1,
        connection_count=60,
        failed_connection_count=0,
        syn_count=20,
        rst_count=0,
        average_packet_size=500
    )

    hits, anomaly, risk, classification = analyze(f)

    assert any(h[0] == "IDS-001" for h in hits)