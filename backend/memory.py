from collections import defaultdict
from datetime import datetime

class SuspicionMemory:
    def __init__(self):
        self.ip_scores = defaultdict(list)
        self.user_scores = defaultdict(list)
        self.event_log = []
        self.confirmed_threats = []

    def record_event(self, event: dict):
        self.event_log.append({
            **event,
            "received_at": datetime.utcnow().isoformat()
        })
        if len(self.event_log) > 500:
            self.event_log = self.event_log[-500:]

    def update_suspicion(self, entity_type: str, entity_id: str, delta: float, reason: str):
        store = self.ip_scores if entity_type == "ip" else self.user_scores
        store[entity_id].append({
            "delta": delta,
            "reason": reason,
            "timestamp": datetime.utcnow().isoformat()
        })

    def get_suspicion_context(self, ip: str, user: str) -> dict:
        ip_history = self.ip_scores.get(ip, [])
        user_history = self.user_scores.get(user, [])
        ip_score = sum(h["delta"] for h in ip_history[-10:])
        user_score = sum(h["delta"] for h in user_history[-10:])
        return {
            "ip": ip,
            "ip_cumulative_suspicion": round(ip_score, 2),
            "ip_recent_reasons": [h["reason"] for h in ip_history[-3:]],
            "user": user,
            "user_cumulative_suspicion": round(user_score, 2),
            "user_recent_reasons": [h["reason"] for h in user_history[-3:]],
            "ip_event_count_today": len(ip_history)
        }

    def get_recent_events_for_ip(self, ip: str, n: int = 50) -> list:
        return [e for e in self.event_log if e.get("source_ip") == ip][-n:]

memory = SuspicionMemory()
