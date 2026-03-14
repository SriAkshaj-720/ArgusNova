import json
import os
from collections import defaultdict
from openai import OpenAI

client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))


class Arbiter:
    def __init__(self):
        self.track_record = {
            "paranoid":        {"correct": 3, "total": 5},
            "skeptic":         {"correct": 4, "total": 5},
            "pattern_matcher": {"correct": 4, "total": 5},
            "narrator":        {"correct": 3, "total": 5},
        }

    def get_weight(self, agent_name):
        rec = self.track_record.get(agent_name, {"correct": 1, "total": 2})
        return round(rec["correct"] / max(rec["total"], 1), 2)

    def update_record(self, agent_name, was_correct):
        if agent_name in self.track_record:
            self.track_record[agent_name]["total"] += 1
            if was_correct:
                self.track_record[agent_name]["correct"] += 1

    async def resolve(self, votes, event):
        weighted_scores = defaultdict(float)

        for vote in votes:
            agent = vote.get("agent", "unknown")
            severity = vote.get("vote", "clean")
            weight = self.get_weight(agent)
            confidence = vote.get("confidence", 0.5)
            weighted_scores[severity] += weight * confidence
            vote["weight"] = weight

        final_severity = max(weighted_scores, key=weighted_scores.get)
        unique_votes = set(v["vote"] for v in votes)
        disagreement = len(unique_votes) >= 3
        arbitration_note = "Consensus reached"

        if disagreement:
            try:
                debate_summary = "\n".join([
                    "{} votes {} (conf {}): {}".format(
                        v.get("agent"), v.get("vote"), v.get("confidence", 0.5),
                        str(v.get("reasoning", v.get("attack_narrative", "")))[:100]
                    )
                    for v in votes
                ])
                response = client.chat.completions.create(
                    model="gpt-3.5-turbo",
                    max_tokens=300,
                    messages=[
                        {
                            "role": "system",
                            "content": "You are a CISO resolving a disagreement between analysts. Return ONLY valid JSON with no extra text: {\"final_severity\": \"critical or high or medium or low or clean\", \"arbitration_reason\": \"one sentence\", \"overruled\": \"agent name or none\"}"
                        },
                        {
                            "role": "user",
                            "content": "Event: {}\n\nVotes:\n{}".format(json.dumps(event), debate_summary)
                        }
                    ]
                )
                raw = response.choices[0].message.content.strip()
                if "```" in raw:
                    raw = raw.split("```")[1]
                    if raw.startswith("json"):
                        raw = raw[4:]
                arb = json.loads(raw.strip())
                final_severity = arb.get("final_severity", final_severity)
                arbitration_note = arb.get("arbitration_reason", "Debate resolved")
            except Exception as e:
                arbitration_note = "Auto-resolved: {}".format(str(e)[:50])

        narrator_vote = next((v for v in votes if v.get("agent") == "narrator"), {})
        pattern_vote = next((v for v in votes if v.get("agent") == "pattern_matcher"), {})

        return {
            "final_severity": final_severity,
            "weighted_scores": dict(weighted_scores),
            "agent_votes": votes,
            "arbitration_note": arbitration_note,
            "was_debated": disagreement,
            "attack_narrative": narrator_vote.get("attack_narrative", ""),
            "kill_chain_stage": narrator_vote.get("kill_chain_stage", "unknown"),
            "attacker_goal": narrator_vote.get("attacker_goal", ""),
            "known_attack_family": pattern_vote.get("known_attack_family"),
            "agent_weights": {a: self.get_weight(a) for a in self.track_record}
        }


arbiter = Arbiter()