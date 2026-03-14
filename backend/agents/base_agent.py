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


async def run_agent(name, system_prompt, event):

    memory = get_memory()
    dna = get_dna()

    context = memory.get_suspicion_context(
        event.get("source_ip", ""),
        event.get("user", "")
    )

    dna_match = dna.match(event)

    payload = {
        "event": event,
        "suspicion_context": context,
        "dna_match": dna_match
    }

    try:

        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            max_tokens=500,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": json.dumps(payload)}
            ]
        )

        raw = response.choices[0].message.content.strip()

        if "```" in raw:
            parts = raw.split("```")
            result = None

            for part in parts:
                part = part.strip()

                if part.startswith("json"):
                    part = part[4:].strip()

                try:
                    result = json.loads(part)
                    break
                except Exception:
                    continue

            if result is None:
                result = {
                    "vote": "medium",
                    "confidence": 0.5,
                    "reasoning": "Parse error",
                    "suspicion_delta": 0.1
                }

        else:
            result = json.loads(raw)

    except Exception:

        # Local fallback logic if API fails or rate limited
        if event.get("failed_attempts", 0) > 50:

            result = {
                "vote": "high",
                "confidence": 0.8,
                "reasoning": "Detected brute force pattern",
                "suspicion_delta": 0.6
            }

        elif event.get("ports_scanned", 0) > 300:

            result = {
                "vote": "high",
                "confidence": 0.75,
                "reasoning": "Large port scan detected",
                "suspicion_delta": 0.5
            }

        else:

            result = {
                "vote": "medium",
                "confidence": 0.5,
                "reasoning": "Fallback local analysis",
                "suspicion_delta": 0.2
            }

    result["agent"] = name
    result["weight"] = 0.6

    memory.update_suspicion(
        "ip",
        event.get("source_ip", "unknown"),
        result.get("suspicion_delta", 0.0),
        "{}: {}".format(name, str(result.get("reasoning", ""))[:60])
    )

    return result