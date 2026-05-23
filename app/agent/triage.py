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
