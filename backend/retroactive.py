import json
import os
from openai import OpenAI

client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))


def get_memory():
    from memory import memory
    return memory


def get_dna():
    from dna import dna
    return dna


async def retroactive_scan(confirmed_event):
    memory = get_memory()
    dna = get_dna()

    ip = confirmed_event.get("source_ip", "")
    past_events = memory.get_recent_events_for_ip(ip, n=50)

    if not past_events:
        return {
            "patient_zero": None,
            "missed_events": [],
            "attack_timeline": "No prior events found for this IP.",
            "missed_because": ""
        }

    try:
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            max_tokens=600,
            messages=[
                {
                    "role": "system",
                    "content": "You are performing post-incident forensic analysis. A CRITICAL threat was confirmed. Find the earliest missed signal. Return ONLY valid JSON with no extra text: {\"patient_zero_index\": 0, \"patient_zero_event\": {}, \"missed_because\": \"one sentence\", \"attack_timeline\": \"2 sentences\", \"earliest_detectable_at\": \"timestamp\"}"
                },
                {
                    "role": "user",
                    "content": json.dumps({
                        "confirmed_threat": confirmed_event,
                        "historical_events": past_events
                    })
                }
            ]
        )
        raw = response.choices[0].message.content.strip()
        if "```" in raw:
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        result = json.loads(raw.strip())
    except Exception as e:
        result = {
            "patient_zero": None,
            "missed_events": [],
            "attack_timeline": "Retroactive analysis error: {}".format(str(e)[:80]),
            "missed_because": ""
        }

    dna.store(
        confirmed_event,
        "Auto-learned: {} from {}".format(confirmed_event.get("event_type", "unknown"), ip)
    )

    return result