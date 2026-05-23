import json
import random
import uuid
from datetime import datetime, timezone
from pathlib import Path

class AlertSimulator:
    def __init__(self):
        # Locate the scenarios directory relative to this file
        self.scenarios_dir = Path(__file__).parent / "scenarios"
        self.scenarios = {}
        
        scenario_files = {
            "brute_force": "brute_force.json",
            "lateral_movement": "lateral_movement.json",
            "data_exfil": "data_exfil.json"
        }
        
        for key, filename in scenario_files.items():
            filepath = self.scenarios_dir / filename
            with open(filepath, "r", encoding="utf-8") as f:
                self.scenarios[key] = json.load(f)

    def get_alert(self, scenario: str) -> dict:
        if scenario not in self.scenarios:
            raise ValueError(f"Unknown scenario: {scenario}. Choose from {list(self.scenarios.keys())}")
        
        # Create a copy to avoid mutating the loaded template
        alert = json.loads(json.dumps(self.scenarios[scenario]))
        
        # Replace alert_id and timestamp with fresh values
        alert["alert_id"] = str(uuid.uuid4())
        alert["timestamp"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        
        return alert

    def get_random_alert(self) -> dict:
        scenario = random.choice(list(self.scenarios.keys()))
        return self.get_alert(scenario)

if __name__ == "__main__":
    simulator = AlertSimulator()
    random_alert = simulator.get_random_alert()
    print(json.dumps(random_alert, indent=2))
