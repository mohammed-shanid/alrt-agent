import os
import json
import uuid
from google import genai
from dotenv import load_dotenv

from app.agent.state import InvestigationState
from app.agent.tools import (
    check_ip_abuseipdb,
    query_log_context,
    check_ip_virustotal,
    correlate_events
)
from app.agent.prompts import CLASSIFY_PROMPT, REPORT_PROMPT

# Load environment variables
load_dotenv()

# Configure Gemini API
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
client = None
if GEMINI_API_KEY:
    client = genai.Client(api_key=GEMINI_API_KEY)

MODEL_NAME = "gemini-1.5-flash"

def call_llm(prompt: str) -> str:
    """
    Generates content for the given prompt using the Gemini client,
    and returns the response text. Returns an empty string on failure.
    """
    try:
        if not client:
            raise ValueError("Gemini client is not configured. Please check GEMINI_API_KEY.")
        response = client.models.generate_content(
            model=MODEL_NAME,
            contents=prompt,
        )
        return response.text
    except Exception as e:
        print(f"Error calling Gemini API: {e}")
        return ""

def classify_alert(state: InvestigationState) -> InvestigationState:
    """
    Classifies the raw alert using the LLM and updates the state with extracted fields.
    """
    alert_json_str = json.dumps(state.raw_alert, indent=2)
    prompt = CLASSIFY_PROMPT.format(alert_json=alert_json_str)
    
    response_text = call_llm(prompt)
    
    # Strip markdown backticks and clean up the response
    cleaned_response = response_text.strip()
    if cleaned_response.startswith("```"):
        # Split by newline to remove the opening ```json or ```
        lines = cleaned_response.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        cleaned_response = "\n".join(lines).strip()
    else:
        cleaned_response = cleaned_response.strip("`").strip()

    try:
        data = json.loads(cleaned_response)
        state.alert_type = data.get("alert_type", "unknown")
        state.severity = data.get("severity", "medium")
        state.source_ip = data.get("source_ip", "")
        state.target_user = data.get("target_user", "")
        state.affected_system = data.get("affected_system", "")
        
        state.add_trace(
            "CLASSIFY", 
            f"Alert classified as {state.alert_type} — severity {state.severity} — source IP {state.source_ip}"
        )
    except Exception as e:
        state.alert_type = "unknown"
        state.add_trace("CLASSIFY", f"Classification failed to parse JSON: {str(e)}")
        
    return state

def enrich_iocs(state: InvestigationState) -> InvestigationState:
    """
    Enriches the source IP using AbuseIPDB and VirusTotal APIs.
    """
    if not state.source_ip:
        state.add_trace("IOC_ENRICHMENT", "No IP to enrich")
        return state

    abuseipdb_res = check_ip_abuseipdb(state.source_ip)
    virustotal_res = check_ip_virustotal(state.source_ip)

    if not hasattr(state, "ioc_findings") or state.ioc_findings is None:
        state.ioc_findings = {}

    state.ioc_findings["abuseipdb"] = abuseipdb_res
    state.ioc_findings["virustotal"] = virustotal_res

    score = abuseipdb_res.get("abuse_confidence_score", 0)
    isp = abuseipdb_res.get("isp") or ""
    verdict = virustotal_res.get("verdict", "unknown")
    malicious = virustotal_res.get("malicious_votes", 0)

    summary_string = f"AbuseIPDB score: {score}, ISP: {isp} — VirusTotal verdict: {verdict} with {malicious} malicious votes"

    if "tor" in isp.lower():
        state.ioc_findings["is_tor"] = True

    state.add_trace("IOC_ENRICHMENT", summary_string)
    return state

def investigate_logs(state: InvestigationState) -> InvestigationState:
    """
    Queries log context and correlates events to identify attack patterns.
    """
    log_results = query_log_context(state.source_ip, state.target_user)
    
    if not hasattr(state, "tool_results") or state.tool_results is None:
        state.tool_results = {}
        
    state.tool_results["log_context"] = log_results
    
    correlation_results = correlate_events(state.raw_alert, log_results)
    state.tool_results["correlation"] = correlation_results
    
    state.correlated_events = log_results.get("matched_events", [])
    
    total_matched = log_results.get("total_matched", 0)
    patterns = correlation_results.get("patterns_detected", [])
    patterns_str = ", ".join(patterns) if patterns else "none"
    
    trace_msg = f"Matched {total_matched} events. Patterns detected: {patterns_str}"
    state.add_trace("LOG_INVESTIGATION", trace_msg)
    
    return state

class TriageAgent:
    """
    Agent responsible for orchestrating the triage, enrichment, log investigation,
    and report generation for security alerts.
    """
    def run(self, alert: dict) -> InvestigationState:
        alert_id = str(uuid.uuid4())
        state = InvestigationState(alert_id=alert_id)
        state.raw_alert = alert
        state.status = "running"
        
        try:
            state.add_trace("AGENT_START", "Received alert, beginning investigation")
            
            # 1. Classify the alert
            state = classify_alert(state)
            
            # 2. Enrich Indicators of Compromise
            state = enrich_iocs(state)
            
            # 3. Investigate logs and correlate events
            state = investigate_logs(state)
            
            # Format reasoning trace for the prompt
            trace_lines = []
            for t in getattr(state, "reasoning_trace", []):
                if isinstance(t, dict):
                    trace_lines.append(f"[{t.get('step', '')}] {t.get('detail', '')}")
                else:
                    trace_lines.append(str(t))
            reasoning_trace_str = "\n".join(trace_lines)
            
            # 4. Generate the final report
            report_prompt = REPORT_PROMPT.format(
                alert=json.dumps(state.raw_alert, indent=2),
                ioc_findings=json.dumps(getattr(state, "ioc_findings", {}), indent=2),
                correlated_events=json.dumps(getattr(state, "correlated_events", []), indent=2),
                mitre_techniques=getattr(state, "alert_type", "Unknown"),
                reasoning_trace=reasoning_trace_str
            )
            
            state.report = call_llm(report_prompt)
            state.add_trace("REPORT_GENERATED", "Investigation report generated successfully")
            state.status = "complete"
            
        except Exception as e:
            state.add_trace("AGENT_ERROR", f"An error occurred during investigation: {str(e)}")
            state.status = "failed"
            
        return state

if __name__ == "__main__":
    from simulator.generator import AlertSimulator
    
    print("Initializing Alert Simulator...")
    simulator = AlertSimulator()
    brute_force_alert = simulator.get_alert("brute_force")
    
    print("Running TriageAgent on brute_force scenario...")
    agent = TriageAgent()
    result_state = agent.run(brute_force_alert)
    
    print("\n=== REASONING TRACE ===")
    for trace in getattr(result_state, "reasoning_trace", []):
        if isinstance(trace, dict):
            print(f"[{trace.get('step')}] {trace.get('detail')}")
        else:
            print(trace)
            
    print("\n=== GENERATED REPORT ===")
    print(getattr(result_state, "report", "No report generated."))
