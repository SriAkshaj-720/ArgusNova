import random
import uuid
import psutil
from datetime import datetime

ATTACK_TYPES = ["brute_force", "port_scan", "sql_injection", "ddos", "privilege_escalation"]
NORMAL_USERS = ["alice", "bob", "carol", "dave", "system"]
MALICIOUS_IPS = ["192.168.1.103", "10.0.0.254", "172.16.0.99"]


def get_live_network_events():
    events = []
    try:
        connections = psutil.net_connections(kind="inet")
        net_stats = psutil.net_io_counters()
        for conn in connections[:3]:
            if conn.raddr and conn.status == "ESTABLISHED":
                events.append({
                    "id": str(uuid.uuid4()),
                    "timestamp": datetime.utcnow().isoformat(),
                    "source_ip": str(conn.raddr.ip),
                    "destination_port": conn.laddr.port if conn.laddr else 0,
                    "event_type": "live_connection",
                    "failed_attempts": 0,
                    "bytes_transferred": int(net_stats.bytes_recv),
                    "ports_scanned": 0,
                    "user": "system",
                    "data_source": "LIVE"
                })
    except Exception:
        pass
    return events


def generate_background_event():
    is_attack = random.random() < 0.25
    return {
        "id": str(uuid.uuid4()),
        "timestamp": datetime.utcnow().isoformat(),
        "source_ip": random.choice(MALICIOUS_IPS) if is_attack else "10.0.{}.{}".format(
            random.randint(1, 50), random.randint(1, 200)),
        "destination_port": random.choice([22, 3306, 5432, 80, 443]),
        "event_type": random.choice(ATTACK_TYPES) if is_attack else "normal_access",
        "failed_attempts": random.randint(50, 200) if is_attack else random.randint(0, 2),
        "bytes_transferred": random.randint(100000, 5000000) if is_attack else random.randint(100, 5000),
        "ports_scanned": random.randint(500, 1500) if is_attack and random.random() < 0.3 else 0,
        "user": random.choice(NORMAL_USERS),
        "data_source": "SIMULATED"
    }


def generate_attack_scenario():
    return [
        {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat(),
            "source_ip": "192.168.1.103",
            "event_type": "port_scan",
            "ports_scanned": 1500,
            "failed_attempts": 0,
            "bytes_transferred": 5000,
            "destination_port": 0,
            "user": "unknown",
            "data_source": "LIVE_ATTACK"
        },
        {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat(),
            "source_ip": "192.168.1.103",
            "event_type": "brute_force",
            "failed_attempts": 147,
            "destination_port": 22,
            "bytes_transferred": 200,
            "ports_scanned": 0,
            "user": "root",
            "data_source": "LIVE_ATTACK"
        },
        {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat(),
            "source_ip": "192.168.1.103",
            "event_type": "privilege_escalation",
            "failed_attempts": 0,
            "destination_port": 22,
            "bytes_transferred": 1200,
            "ports_scanned": 0,
            "user": "root",
            "data_source": "LIVE_ATTACK"
        },
        {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat(),
            "source_ip": "192.168.1.103",
            "event_type": "data_exfiltration",
            "failed_attempts": 0,
            "destination_port": 443,
            "bytes_transferred": 4800000,
            "ports_scanned": 0,
            "user": "root",
            "data_source": "LIVE_ATTACK"
        }
    ]