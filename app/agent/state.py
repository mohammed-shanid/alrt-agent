from dataclasses import dataclass, field
import dataclasses
from typing import List, Dict, Any

@dataclass
class InvestigationState:
    alert_id: str
    raw_alert: dict
    alert_type: str = ""
    severity: str = "unknown"
    source_ip: str = ""
    target_user: str = ""
    affected_system: str = ""
    timestamp: str = ""
    reasoning_trace: List[str] = field(default_factory=list)
    tool_results: Dict[str, Any] = field(default_factory=dict)
    ioc_findings: Dict[str, Any] = field(default_factory=dict)
    correlated_events: List[Any] = field(default_factory=list)
    mitre_techniques: List[Any] = field(default_factory=list)
    report: str = ""
    status: str = "pending"

    def add_trace(self, step_name: str, detail: str) -> None:
        """Appends a formatted string like [STEP_NAME] detail to reasoning_trace."""
        self.reasoning_trace.append(f"[{step_name}] {detail}")

    def add_tool_result(self, tool_name: str, result: dict) -> None:
        """Saves result into tool_results under that tool name."""
        self.tool_results[tool_name] = result

    def to_dict(self) -> Dict[str, Any]:
        """Returns all fields as a plain Python dict."""
        return dataclasses.asdict(self)
