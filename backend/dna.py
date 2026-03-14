import numpy as np
from sklearn.metrics.pairwise import cosine_similarity


class ThreatDNA:
    def __init__(self):
        self.library = []

    def fingerprint(self, event: dict) -> np.ndarray:
        return np.array([
            min(event.get("failed_attempts", 0) / 200, 1.0),
            min(event.get("bytes_transferred", 0) / 5000000, 1.0),
            1.0 if event.get("destination_port") in [22, 3306, 5432, 23, 21] else 0.0,
            1.0 if event.get("event_type") == "brute_force" else 0.0,
            1.0 if event.get("event_type") == "port_scan" else 0.0,
            1.0 if event.get("event_type") == "data_exfiltration" else 0.0,
            1.0 if event.get("event_type") == "privilege_escalation" else 0.0,
            min(event.get("ports_scanned", 0) / 1000, 1.0),
        ], dtype=float)

    def store(self, event: dict, threat_name: str):
        vec = self.fingerprint(event)
        self.library.append({"vector": vec, "name": threat_name, "event": event})

    def match(self, event: dict, threshold: float = 0.85):
        if not self.library:
            return None
        query = self.fingerprint(event).reshape(1, -1)
        library_vecs = np.array([d["vector"] for d in self.library])
        similarities = cosine_similarity(query, library_vecs)[0]
        best_idx = int(np.argmax(similarities))
        best_score = float(similarities[best_idx])
        if best_score >= threshold:
            match = self.library[best_idx]
            return {
                "matched_pattern": match["name"],
                "similarity_score": round(best_score, 3),
                "matched_event": match["event"]
            }
        return None

    def seed_known_attacks(self):
        self.store(
            {"failed_attempts": 180, "destination_port": 22, "event_type": "brute_force", "bytes_transferred": 200, "ports_scanned": 0},
            "SSH brute force"
        )
        self.store(
            {"ports_scanned": 900, "event_type": "port_scan", "bytes_transferred": 5000, "failed_attempts": 0, "destination_port": 0},
            "Nmap full scan"
        )
        self.store(
            {"bytes_transferred": 4800000, "event_type": "data_exfiltration", "destination_port": 443, "failed_attempts": 0, "ports_scanned": 0},
            "Large exfil via HTTPS"
        )
        self.store(
            {"event_type": "privilege_escalation", "failed_attempts": 0, "destination_port": 22, "bytes_transferred": 1200, "ports_scanned": 0},
            "Privilege escalation via SSH"
        )


dna = ThreatDNA()
dna.seed_known_attacks()