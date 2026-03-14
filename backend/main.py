import asyncio
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from dotenv import load_dotenv

load_dotenv()

from simulator import generate_background_event, generate_attack_scenario, get_live_network_events
from memory import memory
from arbiter import arbiter
from retroactive import retroactive_scan
from agents.base_agent import run_agent
from agents.paranoid import SYSTEM_PROMPT as PARANOID
from agents.skeptic import SYSTEM_PROMPT as SKEPTIC
from agents.pattern_matcher import SYSTEM_PROMPT as PATTERN
from agents.narrator import SYSTEM_PROMPT as NARRATOR

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

connected_clients = []
incident_log = []


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    connected_clients.append(websocket)
    for incident in incident_log[-20:]:
        try:
            await websocket.send_text(json.dumps(incident))
        except Exception:
            pass
    try:
        while True:
            await asyncio.sleep(1)
    except WebSocketDisconnect:
        if websocket in connected_clients:
            connected_clients.remove(websocket)
    except Exception:
        if websocket in connected_clients:
            connected_clients.remove(websocket)


async def broadcast(payload: dict):
    incident_log.append(payload)
    if len(incident_log) > 200:
        incident_log.pop(0)
    for client in connected_clients[:]:
        try:
            await client.send_text(json.dumps(payload))
        except Exception:
            if client in connected_clients:
                connected_clients.remove(client)


async def process_event(event: dict):
    try:
        memory.record_event(event)

        event_type = event.get("event_type", "")
        forced_severity = None
        if event_type == "data_exfiltration":
            forced_severity = "critical"
        elif event_type == "privilege_escalation":
            forced_severity = "critical"
        elif event_type == "brute_force":
            forced_severity = "high"
        elif event_type == "port_scan":
            forced_severity = "medium"
        elif event_type == "ddos":
            forced_severity = "high"
        elif event_type == "sql_injection":
            forced_severity = "high"
        elif event_type == "normal_access" or event_type == "live_connection":
            forced_severity = "clean"

        votes = await asyncio.gather(
            run_agent("paranoid", PARANOID, event),
            run_agent("skeptic", SKEPTIC, event),
            run_agent("pattern_matcher", PATTERN, event),
            run_agent("narrator", NARRATOR, event),
        )

        verdict = await arbiter.resolve(list(votes), event)

        if forced_severity:
            verdict["final_severity"] = forced_severity

        verdict["event"] = event
        verdict["id"] = event.get("id", "")
        verdict["timestamp"] = event.get("timestamp", "")

        if verdict.get("final_severity") == "critical":
            try:
                retro = await retroactive_scan(event)
                verdict["retroactive_analysis"] = retro
            except Exception as e:
                print("Retroactive error:", e)

        await broadcast(verdict)
        print("Event processed: {} -> {}".format(
            event.get("event_type"), verdict.get("final_severity")))
    except Exception as e:
        print("process_event error:", e)


async def log_injector():
    while True:
        try:
            live_events = get_live_network_events()
            for event in live_events:
                await process_event(event)
        except Exception as e:
            print("Injector error:", e)
        await asyncio.sleep(2)


@app.on_event("startup")
async def startup():
    asyncio.create_task(log_injector())


@app.post("/demo")
async def run_demo():
    async def _run():
        scenario = generate_attack_scenario()
        for event in scenario:
            await process_event(event)
            await asyncio.sleep(5)
    asyncio.create_task(_run())
    return {"status": "demo started"}


@app.get("/health")
async def health():
    return {
        "status": "running",
        "incidents": len(incident_log),
        "clients": len(connected_clients)
    }


@app.get("/")
async def root():
    html_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dashboard.html")
    return FileResponse(html_path)