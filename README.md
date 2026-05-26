<div align="center">

<img src="https://img.shields.io/badge/AlrtAgent-Autonomous%20SOC%20Triage-red?style=for-the-badge&logo=shield&logoColor=white" alt="AlrtAgent"/>

# 🔴 AlrtAgent
### Autonomous SOC Alert Triage Agent

**An AI-native security analyst that receives SIEM alerts, investigates autonomously, and delivers analyst-grade incident reports — in 30 seconds.**

[![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Python](https://img.shields.io/badge/Python_3.11-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Docker](https://img.shields.io/badge/Docker-2496ED?style=flat-square&logo=docker&logoColor=white)](https://docker.com)
[![ChromaDB](https://img.shields.io/badge/ChromaDB-FF6B35?style=flat-square&logo=database&logoColor=white)](https://chromadb.com)
[![DeepSeek](https://img.shields.io/badge/DeepSeek_V3-4A90D9?style=flat-square&logo=openai&logoColor=white)](https://deepseek.com)
[![Streamlit](https://img.shields.io/badge/Streamlit-FF4B4B?style=flat-square&logo=streamlit&logoColor=white)](https://streamlit.io)

[![Live Demo](https://img.shields.io/badge/🚀_Live_Demo-Streamlit_Cloud-FF4B4B?style=flat-square)](YOUR_STREAMLIT_URL)
[![API Docs](https://img.shields.io/badge/📡_API_Docs-Render-46E3B7?style=flat-square)](YOUR_RENDER_URL/docs)
[![GitHub Stars](https://img.shields.io/github/stars/YOUR_USERNAME/alrt-agent?style=flat-square&color=yellow)](https://github.com/YOUR_USERNAME/alrt-agent/stargazers)

---

> *"Automated what a Tier-1 SOC analyst takes 30 minutes to do — in 30 seconds."*

**[🎥 Watch Demo Video](YOUR_LOOM_URL)** • **[🚀 Live Demo](YOUR_STREAMLIT_URL)** • **[📡 API](YOUR_RENDER_URL/docs)**

</div>

---

## 🧠 What Is AlrtAgent?

Most SOC teams receive **3,800+ alerts per day**. **62% go uninvestigated** due to analyst overload. Tier-1 triage — the manual process of checking an IP, digging through logs, correlating events, and writing an investigation report — takes a skilled analyst **20–40 minutes per alert**.

**AlrtAgent eliminates that bottleneck.**

It is an autonomous agent that:
- **Receives** SIEM alerts via webhook or manual upload
- **Enriches** IOCs against real threat intelligence databases
- **Correlates** multi-event attack sequences from log data
- **Maps** attacker behavior to MITRE ATT&CK techniques via RAG
- **Generates** a complete analyst-grade investigation report

No human in the loop. No templates. Real conclusions.

---

## 📸 Screenshots

### Dashboard — Live Investigation
![AlrtAgent Dashboard](YOUR_SCREENSHOT_URL_DASHBOARD)
*Real-time reasoning trace showing every step the agent took to reach its conclusions*

### Investigation Report Output
![Investigation Report](YOUR_SCREENSHOT_URL_REPORT)
*Analyst-grade report with executive summary, IOC analysis, MITRE mapping, and recommended actions*

### File Upload — Forensic Mode
![File Upload](YOUR_SCREENSHOT_URL_UPLOAD)
*Upload raw JSON alerts or syslog files for instant forensic investigation*

---

## ⚡ How It Works

```
SIEM Alert / Uploaded Log
          │
          ▼
┌─────────────────────┐
│   FastAPI Backend   │  POST /alert
│   (Ingestion Layer) │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────────────────────────────────────┐
│                  Agent Loop (triage.py)              │
│                                                      │
│  1. CLASSIFY   → Extract alert type, severity, IPs  │
│  2. IOC ENRICH → AbuseIPDB + VirusTotal API calls   │
│  3. LOG SEARCH → Correlate events from log store    │
│  4. PATTERN    → Detect attack sequences            │
│  5. MITRE RAG  → ChromaDB technique retrieval       │
│  6. REPORT GEN → DeepSeek V3 narrative generation   │
└──────────────────────┬──────────────────────────────┘
                       │
          ┌────────────┼────────────┐
          ▼            ▼            ▼
   AbuseIPDB      VirusTotal    ChromaDB
   (real API)     (real API)    (MITRE RAG)
                       │
                       ▼
          ┌────────────────────────┐
          │   Streamlit Dashboard  │
          │  Trace + Report + UI   │
          └────────────────────────┘
```

---

## 🎯 Reasoning Trace — What The Agent Actually Does

Every investigation produces a visible step-by-step trace:

```
✅ [AGENT_START]      Received alert, beginning investigation
✅ [CLASSIFY]         Alert classified as brute_force — severity HIGH — source IP 185.220.101.47
✅ [IOC_ENRICHMENT]   AbuseIPDB score: 100, ISP: Network for Tor-Exit traffic
                      VirusTotal verdict: malicious with 13 malicious votes
✅ [LOG_INVESTIGATION] Matched 7 events
                      Patterns: credential_brute_force, successful_auth_after_brute_force,
                      lateral_movement_detected, privilege_escalation_attempt
✅ [MITRE_LOOKUP]     Retrieved 3 MITRE ATT&CK techniques
✅ [REPORT_GENERATED] Investigation report generated successfully
```

---

## 📊 Performance

| Metric | Manual SOC Analyst | AlrtAgent |
|--------|-------------------|-----------|
| Time to triage | 20–40 minutes | **~30 seconds** |
| IOC enrichment | Manual lookup | **Automated (2 APIs)** |
| Log correlation | Manual grep/query | **Automated pattern detection** |
| MITRE mapping | Analyst knowledge | **RAG-assisted retrieval** |
| Report writing | 15–20 minutes | **LLM-generated** |
| Consistency | Variable | **Deterministic workflow** |

---

## 🛡️ Sample Investigation Report

> **The following report was generated autonomously by AlrtAgent from a synthetic brute-force scenario. No human wrote this.**

---

**Alert ID:** `c901c772-6322-4bcd-adea-4db5c2a4f862`
**Severity:** 🔴 CRITICAL

### Executive Summary
A confirmed successful SSH brute-force attack against `prod-server-01` targeting the `admin` user. The attack originated from `185.220.101.47` — a known Tor exit node with AbuseIPDB confidence score of **100/100** and **13 malicious votes** on VirusTotal. After 847 login attempts the threat actor gained administrative access and immediately executed post-exploitation commands including credential harvesting (`cat /etc/passwd`) and lateral movement (`ssh 10.0.0.14`).

### MITRE ATT&CK Mapping
| Technique ID | Name | Observed Behavior |
|---|---|---|
| T1110.001 | Password Guessing | 847 failed SSH attempts |
| T1078.003 | Valid Local Accounts | Successful admin login |
| T1021.004 | SSH Lateral Movement | `ssh 10.0.0.14` post-compromise |
| T1003 | OS Credential Dumping | `cat /etc/passwd` execution |

### Top Recommended Actions
1. **Immediate:** Isolate `prod-server-01` from network
2. **Immediate:** Block `185.220.101.47` at perimeter firewall
3. **Immediate:** Force password reset for `admin` account
4. **Within 1hr:** Investigate `10.0.0.14` for lateral movement indicators
5. **Within 24hrs:** Implement fail2ban + MFA on all production SSH

---

## 🚀 Quick Start

### Option 1 — Docker (Recommended)
```bash
git clone https://github.com/YOUR_USERNAME/alrt-agent
cd alrt-agent
cp .env.example .env
# Fill in your API keys in .env
docker-compose up
```
Open `http://localhost:8501` — click any attack scenario — watch the agent work.

### Option 2 — Local
```bash
git clone https://github.com/YOUR_USERNAME/alrt-agent
cd alrt-agent
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Fill in your API keys in .env

# Terminal 1
uvicorn app.main:app --reload --port 8000

# Terminal 2
streamlit run ui/dashboard.py
```

---

## 🔑 API Keys Required

| Service | Purpose | Cost | Link |
|---------|---------|------|------|
| DeepSeek V3 | LLM reasoning + report generation | ~$0.001/investigation | [platform.deepseek.com](https://platform.deepseek.com) |
| AbuseIPDB | IP reputation + Tor detection | Free (1000/day) | [abuseipdb.com](https://abuseipdb.com) |
| VirusTotal | IP malicious vote count | Free (500/day) | [virustotal.com](https://virustotal.com) |
| Gemini Flash | Alternative LLM (optional) | Free tier | [aistudio.google.com](https://aistudio.google.com) |

---

## 🏗️ Architecture

```
alrt-agent/
├── app/
│   ├── main.py              # FastAPI — alert ingestion + investigation API
│   ├── agent/
│   │   ├── triage.py        # Core agent loop (THE brain)
│   │   ├── tools.py         # AbuseIPDB, VirusTotal, log search, correlation
│   │   ├── prompts.py       # LLM prompt templates
│   │   └── state.py         # InvestigationState schema
│   ├── rag/
│   │   ├── loader.py        # ChromaDB MITRE knowledge loader
│   │   └── retriever.py     # Semantic technique search
│   └── reports/
│       └── store.py         # Report persistence
├── simulator/
│   ├── generator.py         # Synthetic SIEM alert generator
│   └── scenarios/           # 3 pre-built attack scenarios
│       ├── brute_force.json
│       ├── lateral_movement.json
│       └── data_exfil.json
├── ui/
│   └── dashboard.py         # Streamlit — trace + report UI
├── data/
│   ├── mitre_snippets/      # MITRE ATT&CK knowledge base
│   └── sample_logs/         # Synthetic syslog data
├── docker-compose.yml
└── requirements.txt
```

---

## 📡 API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Service health check |
| `POST` | `/alert` | Submit alert for investigation |
| `GET` | `/investigation/{id}` | Get full investigation result |
| `GET` | `/investigations` | List all investigations |
| `GET` | `/docs` | Interactive Swagger UI |

**Example:**
```bash
curl -X POST https://YOUR_RENDER_URL/alert \
  -H "Content-Type: application/json" \
  -d '{"alert_type": "brute_force_ssh", "source_ip": "185.220.101.47", "target_user": "admin"}'
```

---

## 🔄 Real-World Integration

AlrtAgent exposes a standard webhook endpoint. Any SIEM can POST alerts to it:

```
Splunk Alert Action  ──→  POST /alert  ──→  AlrtAgent  ──→  Report
IBM QRadar Webhook   ──→  POST /alert  ──→  AlrtAgent  ──→  Report
Elastic SIEM Rule    ──→  POST /alert  ──→  AlrtAgent  ──→  Report
Manual Log Upload    ──→  POST /alert  ──→  AlrtAgent  ──→  Report
```

**Supported input formats:**
- Structured JSON alert (SIEM webhook format)
- Raw syslog lines (`.log` file upload)
- AWS CloudTrail JSON
- Custom JSON with any alert fields

---

## 🧪 Attack Scenarios Included

| Scenario | Attack Type | IOCs | Patterns Detected |
|----------|------------|------|------------------|
| `brute_force` | SSH brute force → successful auth | `185.220.101.47` (Tor, score 100) | 4 patterns |
| `lateral_movement` | Post-compromise SSH pivoting | `10.0.0.12` → `10.0.0.14` | 3 patterns |
| `data_exfil` | Outbound data transfer via HTTPS | `91.108.4.33` | 2 patterns |

---

## 🛣️ Roadmap

- [x] Core autonomous agent loop
- [x] Real IOC enrichment (AbuseIPDB + VirusTotal)
- [x] Multi-event log correlation
- [x] MITRE ATT&CK RAG retrieval
- [x] Analyst-grade report generation
- [x] Streamlit dashboard with live reasoning trace
- [x] File upload for forensic investigation
- [x] Docker deployment
- [ ] Splunk webhook integration
- [ ] Real attack traffic from Kali Linux VM
- [ ] Slack/Teams alert notifications
- [ ] PDF report export
- [ ] Multi-alert campaign detection

---

## 👨‍💻 Built By

**Mohammed Shanid K. S.**
Final Year B.Tech — Cyber Security & Cyber Forensics
Srinivas University Institute of Engineering and Technology

Also built: **[MedRAGShield](YOUR_MEDRAGSHIELD_LINK)** — Adversarial defense framework for medical RAG systems (Published: IEEE TechRxiv)

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-0077B5?style=flat-square&logo=linkedin)](YOUR_LINKEDIN_URL)
[![GitHub](https://img.shields.io/badge/GitHub-Follow-181717?style=flat-square&logo=github)](https://github.com/YOUR_USERNAME)

---

## ⭐ If this project helped you, leave a star — it helps others find it.

<div align="center">

**AlrtAgent** is a portfolio demonstration of autonomous AI-security engineering.
It is not affiliated with any commercial SOC product.

</div>
