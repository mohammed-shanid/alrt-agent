import streamlit as pd
import streamlit as st
import requests
import json
import time

API_URL = "http://localhost:8000"

st.set_page_config(page_title="AlrtAgent — Autonomous SOC Triage", layout="wide")
st.title("AlrtAgent — Autonomous SOC Triage")

# Sidebar
st.sidebar.header("Trigger Investigation")

def trigger_scenario(scenario_name: str):
    try:
        response = requests.post(f"{API_URL}/alert", json={"scenario": scenario_name})
        if response.status_code == 200:
            data = response.json()
            st.session_state["active_alert_id"] = data["alert_id"]
            st.success(f"Triggered investigation: {data['alert_id']}")
        else:
            st.error(f"Error triggering alert: {response.text}")
    except Exception as e:
        st.error(f"Failed to connect to API: {str(e)}")

if st.sidebar.button("Brute Force Attack"):
    trigger_scenario("brute_force")

if st.sidebar.button("Lateral Movement"):
    trigger_scenario("lateral_movement")

if st.sidebar.button("Data Exfiltration"):
    trigger_scenario("data_exfil")

st.sidebar.markdown("---")
if st.sidebar.button("Refresh"):
    st.rerun()

# Main Area
active_alert_id = st.session_state.get("active_alert_id")

if active_alert_id:
    st.subheader(f"Active Investigation: {active_alert_id}")
    
    # Fetch investigation status
    try:
        response = requests.get(f"{API_URL}/investigation/{active_alert_id}")
        if response.status_code == 200:
            data = response.json()
            status = data.get("status", "unknown")
            
            # If still investigating, poll by sleeping and rerunning
            if status == "investigating":
                st.info("Investigation in progress... polling for updates.")
                time.sleep(2)
                st.rerun()
            elif status == "failed":
                st.error(f"Investigation failed: {data.get('error')}")
            
            # Metrics Row
            col1, col2, col3, col4 = st.columns(4)
            alert_type = data.get("alert_type", "N/A")
            severity = data.get("severity", "unknown")
            source_ip = data.get("source_ip", "N/A")
            
            # Calculate total matched events from correlated_events or tool_results
            correlated_events = data.get("correlated_events") or []
            total_events = len(correlated_events)
            
            col1.metric("Alert Type", alert_type)
            col2.metric("Severity", severity.upper())
            col3.metric("Source IP", source_ip)
            col4.metric("Matched Events", total_events)
            
            # Severity Badge
            severity_lower = severity.lower()
            if "critical" in severity_lower:
                st.error("Severity: CRITICAL")
            elif "high" in severity_lower:
                st.warning("Severity: HIGH")
            else:
                st.info(f"Severity: {severity.upper()}")
                
            # Reasoning Trace
            reasoning_trace = data.get("reasoning_trace", [])
            with st.expander("Reasoning Trace", expanded=True):
                if reasoning_trace:
                    for step in reasoning_trace:
                        st.write(f"✅ {step}")
                else:
                    st.write("No reasoning trace steps available yet.")
            
            # Final Report
            st.subheader("Investigation Report")
            report = data.get("report")
            if report:
                st.markdown(report)
            else:
                st.write("Report is being generated...")
                
        elif response.status_code == 404:
            st.error("Investigation not found on the server.")
        else:
            st.error(f"Error fetching investigation: {response.text}")
            
    except Exception as e:
        st.error(f"Failed to fetch investigation details: {str(e)}")
else:
    st.info("Select a scenario from the sidebar to trigger an autonomous SOC triage investigation.")
