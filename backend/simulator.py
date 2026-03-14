import uuid
from datetime import datetime


def get_live_network_events():
    events = []
    try:
        import psutil
        connections = psutil.net_connections(kind="inet")
        net_stats = psutil.net_io_counters()
        seen = set()
        for conn in connections:
            if conn.raddr and conn.status in ["ESTABLISHED", "SYN_RECV", "CLOSE_WAIT", "TIME_WAIT"]:
                key = "{}:{}".format(conn.raddr.ip, conn.laddr.port if conn.laddr else 0)
                if key not in seen:
                    seen.add(key)
                    remote_ip = str(conn.raddr.ip)
                    port = conn.laddr.port if conn.laddr else 0
                    events.append({
                        "id": str(uuid.uuid4()),
                        "timestamp": datetime.utcnow().isoformat(),
                        "source_ip": remote_ip,
                        "destination_port": port,
                        "event_type": "live_connection",
                        "failed_attempts": 0,
                        "bytes_transferred": int(net_stats.bytes_recv),
                        "ports_scanned": 0,
                        "user": "system",
                        "data_source": "LIVE"
                    })
    except Exception as e:
        print("Live monitor error:", e)
    return events


def generate_background_event():
    return None


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