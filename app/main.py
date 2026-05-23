import uuid
import json
import os
import dataclasses
from typing import Optional
from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from app.agent.triage import TriageAgent
from simulator.generator import AlertSimulator

app = FastAPI()

# Add CORS middleware allowing all origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global in-memory storage for investigations
investigations = {}

# Global instances
agent = TriageAgent()
simulator = AlertSimulator()

class AlertRequest(BaseModel):
    scenario: Optional[str] = "random"

def run_triage_task(alert_id: str, alert_data: dict):
    try:
        # Ensure the alert dict has the correct alert_id
        alert_data["alert_id"] = alert_id
        state = agent.run(alert_data)
        investigations[alert_id] = {
            "status": "completed",
            "state": state
        }
    except Exception as e:
        investigations[alert_id] = {
            "status": "failed",
            "error": str(e),
            "state": None
        }

@app.get("/health")
def health_check():
    return {"status": "ok", "service": "AlrtAgent"}

@app.post("/alert")
def trigger_alert(payload: AlertRequest, background_tasks: BackgroundTasks):
    scenario = payload.scenario or "random"
    
    try:
        if scenario == "random":
            alert = simulator.get_random_alert()
        else:
            alert = simulator.get_alert(scenario)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to load scenario '{scenario}': {str(e)}")

    alert_id = str(uuid.uuid4())
    
    investigations[alert_id] = {
        "status": "investigating",
        "state": None
    }
    
    background_tasks.add_task(run_triage_task, alert_id, alert)
    
    return {"alert_id": alert_id, "status": "investigating"}

@app.get("/investigation/{alert_id}")
def get_investigation(alert_id: str):
    if alert_id not in investigations:
        raise HTTPException(status_code=404, detail="Investigation not found")
    
    record = investigations[alert_id]
    status = record["status"]
    state = record["state"]
    
    if state is not None:
        state_dict = dataclasses.asdict(state)
        return {
            "status": status,
            **state_dict
        }
    else:
        return {
            "status": status,
            "alert_id": alert_id,
            "reasoning_trace": [],
            "report": None,
            "error": record.get("error")
        }

@app.get("/investigations")
def list_investigations():
    return [
        {"alert_id": aid, "status": info["status"]}
        for aid, info in investigations.items()
    ]
