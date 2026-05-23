import os
import json
import google.generativeai as genai
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
if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)

MODEL_NAME = "gemini-1.5-flash"

def call_llm(prompt: str) -> str:
    """
    Creates a GenerativeModel instance, generates content for the given prompt,
    and returns the response text. Returns an empty string on failure.
    """
    try:
        model = genai.GenerativeModel(MODEL_NAME)
        response = model.generate_content(prompt)
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
