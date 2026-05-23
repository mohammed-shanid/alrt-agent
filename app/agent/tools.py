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
