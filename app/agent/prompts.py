CLASSIFY_PROMPT = """You are an expert security automation system. Your task is to analyze the following alert JSON and extract key security attributes.

Alert JSON:
{alert_json}

You must return ONLY a valid JSON object with the following fields. Do not include any markdown formatting (such as ```json), explanations, or extra text.

Required JSON fields:
- "alert_type": A string describing the attack category (e.g., "brute_force", "lateral_movement", "data_exfiltration").
- "severity": One of "critical", "high", "medium", or "low".
- "source_ip": The source IP address initiating the activity.
- "target_user": The target username, or an empty string if not applicable.
- "affected_system": The affected hostname or system identifier, or an empty string if not applicable.
- "summary": A single sentence describing exactly what happened.

JSON Output:"""

REPORT_PROMPT = """You are a senior Tier-1 SOC analyst. Write a professional, highly technical, and specific SOC analyst investigation report in markdown format based on the provided security data.

Do not use hedging language such as "may possibly", "perhaps", "could potentially", or "might indicate". State your findings and conclusions with absolute technical confidence based on the evidence.

Input Data:
- Alert Details: {alert}
- IOC Findings: {ioc_findings}
- Correlated Events: {correlated_events}
- MITRE ATT&CK Techniques: {mitre_techniques}
- Reasoning Trace: {reasoning_trace}

Your report MUST contain these exact sections in markdown format:

# Executive Summary
Provide a concise, high-level summary of the incident, the threat actor's actions, and the overall impact.

# Attack Timeline
Reconstruct a chronological timeline of the events, including timestamps, actions, and outcomes.

# IOC Analysis
Analyze the Indicators of Compromise (IPs, users, systems) and their reputation or threat intelligence findings.

# Correlated Events
Detail how the log events correlate with the alert, highlighting patterns like brute force, successful authentication, lateral movement, or privilege escalation.

# MITRE ATT&CK Techniques
Map the observed behaviors to specific MITRE ATT&CK tactics and techniques (e.g., T1110 - Brute Force).

# Severity Assessment
Provide a definitive severity rating (Critical, High, Medium, Low) with a clear, evidence-based justification.

# Recommended Actions
List specific, actionable, and prioritized mitigation and remediation steps for the incident response team.
"""
