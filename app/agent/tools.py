import os
import requests
import json
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Retrieve API keys from environment variables
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

def check_ip_abuseipdb(ip: str) -> dict:
    """
    Calls the AbuseIPDB v2 check endpoint to gather reputation data for an IP address.
    """
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": ABUSEIPDB_API_KEY or "",
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90,
        "verbose": "true"
    }

    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        res_json = response.json()
        data = res_json.get("data", {})

        abuse_confidence_score = data.get("abuseConfidenceScore", 0)
        usage_type = data.get("usageType") or ""
        is_tor = "Tor" in usage_type

        return {
            "ip": ip,
            "abuse_confidence_score": abuse_confidence_score,
            "country_code": data.get("countryCode"),
            "isp": data.get("isp"),
            "total_reports": data.get("totalReports", 0),
            "is_tor": is_tor,
            "is_malicious": abuse_confidence_score > 25
        }
    except Exception as e:
        return {
            "ip": ip,
            "error": True,
            "message": str(e)
        }

def _search_in_log_entry(entry: dict, search_terms: list[str]) -> bool:
    """Recursively checks if any string value in the log entry contains any of the search terms."""
    if not search_terms:
        return False

    def _traverse(data):
        if isinstance(data, str):
            for term in search_terms:
                if term.lower() in data.lower():
                    return True
        elif isinstance(data, dict):
            for value in data.values():
                if _traverse(value):
                    return True
        elif isinstance(data, list):
            for item in data:
                if _traverse(item):
                    return True
        return False

    return _traverse(entry)

def query_log_context(source_ip: str, target_user: str = "", limit: int = 10) -> dict:
    """
    Loads log entries from data/sample_logs/ and searches for matching entries.

    Searches all loaded log entries for any entry where any string field contains
    the source_ip OR the target_user (case insensitive).

    Args:
        source_ip (str): The IP address to search for.
        target_user (str, optional): The target user to search for. Defaults to "".
        limit (int, optional): The maximum number of matching entries to return. Defaults to 10.

    Returns:
        dict: A dictionary containing:
            - "matched_events": list of up to `limit` matching entries.
            - "total_matched": int, the total count of matching entries.
            - "search_terms": list of what was searched for.
    """
    log_data_path = Path(__file__).parent.parent.parent / "data" / "sample_logs"
    all_log_entries = []

    if not log_data_path.is_dir():
        return {
            "matched_events": [],
            "total_matched": 0,
            "search_terms": [term for term in [source_ip, target_user] if term]
        }

    for log_file in log_data_path.glob("*.json"):
        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                content = json.load(f)
                if isinstance(content, list):
                    all_log_entries.extend(content)
                elif isinstance(content, dict):
                    all_log_entries.append(content)
        except json.JSONDecodeError as e:
            print(f"Error decoding JSON from {log_file}: {e}")
        except Exception as e:
            print(f"Error reading {log_file}: {e}")

    matched_events = []
    total_matched = 0
    search_terms_list = [term for term in [source_ip, target_user] if term]

    if not search_terms_list:
        return {
            "matched_events": [],
            "total_matched": 0,
            "search_terms": []
        }

    for entry in all_log_entries:
        if _search_in_log_entry(entry, search_terms_list):
            total_matched += 1
            if len(matched_events) < limit:
                matched_events.append(entry)

    return {
        "matched_events": matched_events,
        "total_matched": total_matched,
        "search_terms": search_terms_list
    }

def check_ip_virustotal(ip: str) -> dict:
    """
    Calls the VirusTotal v3 IP address endpoint to gather reputation data.
    """
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY or ""
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        res_json = response.json()
        
        data = res_json.get("data", {})
        attributes = data.get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)

        if malicious > 2:
            verdict = "malicious"
        elif suspicious > 2:
            verdict = "suspicious"
        else:
            verdict = "clean"

        return {
            "ip": ip,
            "malicious_votes": malicious,
            "suspicious_votes": suspicious,
            "harmless_votes": harmless,
            "verdict": verdict
        }
    except Exception as e:
        return {
            "ip": ip,
            "error": True,
            "message": str(e)
        }
