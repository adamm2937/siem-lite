# 🛡 SIEM-Lite. Automated Threat Detection Platform


> A lightweight, production-style SIEM (Security Information & Event Management) system built in Python.  
> Ingests logs from multiple sources, correlates events using sliding-window rules, fires real-time alerts, and visualises threats on a live dashboard.

![Python](https://img.shields.io/badge/Python-3.12-blue?style=flat-square&logo=python)
![Flask](https://img.shields.io/badge/Flask-3.0-black?style=flat-square&logo=flask)
![Docker](https://img.shields.io/badge/Docker-ready-2496ED?style=flat-square&logo=docker)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-mapped-red?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

---

## Why This Project?

Real SOC work is not about running a single scanner, it is about **continuous monitoring**: ingesting logs from everywhere, correlating events across sources, and surfacing the signal from the noise.

This project implements that full pipeline from scratch, without relying on a hosted SIEM product. Every component is built to mirror how production blue-team infrastructure actually works.

---

## How UI looks like 
<img width="1856" height="970" alt="Screenshot from 2026-04-25 22-38-31" src="https://github.com/user-attachments/assets/ef109660-a533-49ee-bb33-1b68bea82de4" />

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Log Sources                              │
│   auth.log   nginx_access.log   syslog   app.json (custom)     │
└────────────────────────┬────────────────────────────────────────┘
                         │  tail (non-blocking threads)
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Ingestion Engine                             │
│  AuthLogParser · NginxLogParser · SyslogParser · JSONParser     │
│  → normalises every line into a structured event dict           │
└────────────────────────┬────────────────────────────────────────┘
                         │  normalised events
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                   Detection Engine                              │
│  6 stateful rules with sliding-window correlation               │
│  DET-001 SSH Brute Force    DET-004 Web Directory Scan          │
│  DET-002 Success After Fail DET-005 Privilege Escalation        │
│  DET-003 Web Path Traversal DET-006 Port Sweep                  │
└──────────┬─────────────────────────────┬───────────────────────┘
           │ ThreatAlert                 │ raw event
           ▼                             ▼
┌──────────────────────┐     ┌───────────────────────────────────┐
│   Alert Dispatcher   │     │        SQLite Event Store         │
│  Slack · Email · HTTP│     │  events table · alerts table      │
└──────────────────────┘     └───────────────────┬───────────────┘
                                                 │  REST API (Flask)
                                                 ▼
                                      ┌─────────────────┐
                                      │  Live Dashboard  │
                                      │  localhost:5000  │
                                      └─────────────────┘
```

---

## Features

### Multi-source Log Ingestion
- **`auth.log`** - SSH login attempts, sudo commands
- **`nginx_access.log`** - HTTP requests in combined log format
- **`syslog / kern.log`** - OOM kills, segfaults, firewall (UFW) drops
- **Custom JSON logs** - structured output from any app (including the brute-force detector in this repo)

Each parser normalises raw lines into a standard event schema:
```json
{
  "timestamp": "2024-01-15T14:23:01+00:00",
  "source":     "auth.log",
  "event_type": "ssh_login_failure",
  "severity":   "medium",
  "src_ip":     "185.220.101.42",
  "user":       "root",
  "raw":        "Jan 15 14:23:01 server sshd[1234]: Failed password for root..."
}
```

### Correlation-Based Detection Rules

All rules are stateful — they track event history across a sliding time window to detect patterns, not just individual events.

| Rule ID | Name | Technique | Severity |
|---------|------|-----------|----------|
| DET-001 | SSH Brute Force | T1110.001 — Password Guessing | 🔴 High |
| DET-002 | Login Success After Failures | T1078 — Valid Accounts | 🚨 Critical |
| DET-003 | Web Path Traversal / Injection | T1083 — File Discovery | 🔴 High |
| DET-004 | Web Directory Scan | T1595.003 — Wordlist Scanning | 🟠 Medium |
| DET-005 | Privilege Escalation Attempt | T1548.003 — Sudo Abuse | 🔴 High |
| DET-006 | Port Sweep via Firewall Drops | T1046 — Network Service Discovery | 🟠 Medium |

All alerts are tagged with **MITRE ATT&CK** tactic and technique.

### Multi-channel Alerting

Configure via environment variables — no code changes required:

```bash
# Slack
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/XXX/YYY/ZZZ

# Email (Gmail / any SMTP)
SMTP_HOST=smtp.gmail.com
SMTP_USER=you@gmail.com
SMTP_PASS=your_app_password
ALERT_EMAIL=oncall@yourteam.com

# Generic webhook (PagerDuty, custom API, etc.)
WEBHOOK_URL=https://your-endpoint.com/alerts
```

### Live Dashboard

A dark-themed web dashboard at `http://localhost:5000` that updates every 5 seconds:
- Real-time alert feed with severity pills and MITRE tags
- Severity breakdown bar chart
- MITRE ATT&CK tactic frequency heatmap
- Raw event log stream

---

## Quick Start

### Option 1 - Docker (recommended, one command)

```bash
git clone https://github.com/YOUR_USERNAME/siem-lite
cd siem-lite
docker-compose up --build
```

Open `http://localhost:5000`.  
In a second terminal, generate attack traffic:

```bash
python simulate.py
```

### Option 2 - Local Python

```bash
git clone https://github.com/YOUR_USERNAME/siem-lite
cd siem-lite
pip install -r requirements.txt
python main.py
```

---

## Simulating Attacks

The included `simulate.py` generates realistic log entries covering every detection scenario:

```bash
python simulate.py
```

Simulated scenarios:
- SSH brute-force campaigns (multiple IPs)
- Credential stuffing — failures followed by success
- Web directory enumeration (sqlmap, gobuster-style)
- Web injection / path traversal attempts
- Sudo privilege escalation
- Port sweep via firewall drops

---

## Project Structure

```
siem-lite/
├── ingestion/
│   └── log_ingester.py     # File tailer + 4 log parsers
├── detection/
│   └── engine.py           # 6 detection rules + sliding-window correlator
├── alerting/
│   └── dispatcher.py       # Slack, Email, Webhook alerters
├── dashboard/
│   └── index.html          # Live threat dashboard (vanilla JS)
├── storage.py              # SQLite event/alert store + REST query API
├── main.py                 # Flask API server + pipeline orchestrator
├── simulate.py             # Attack scenario generator
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

---

## Adding Custom Detection Rules

Extend the engine with a single class:

```python
# detection/engine.py

class MyCustomRule:
    def evaluate(self, event: dict) -> ThreatAlert | None:
        if event.get("event_type") != "my_event_type":
            return None
        return ThreatAlert(
            rule_id="DET-007",
            title="My Custom Alert",
            description="...",
            severity="high",
            mitre_tactic="...",
            mitre_technique="T1234 — ...",
            event=event,
        )

# Register it:
ALL_RULES.append(MyCustomRule())
```

---

## REST API Reference

| Endpoint | Description |
|----------|-------------|
| `GET /api/stats` | Total events, alerts, critical count |
| `GET /api/alerts?limit=50` | Recent alerts (newest first) |
| `GET /api/events?limit=100` | Recent normalised events |
| `GET /api/events/by-type` | Event counts grouped by type |
| `GET /api/alerts/by-severity` | Alert counts grouped by severity |

---

## How This Fits the Bigger Picture

This project intentionally complements the other tools in this repository:

| Project | Role in a real SOC |
|---------|-------------------|
| Brute Force Detector | Generates structured alerts → feeds into SIEM-Lite via JSON log |
| Vulnerability Scanner (Nmap + OpenVAS) | Asset discovery & risk baselining |
| Cyber Notebook (AI) | Analyst augmentation & threat intel |
| **SIEM-Lite (this)** | **Central detection & response backbone** |

---

## Tech Stack

- **Python 3.12** — core pipeline, parsers, detection engine
- **Flask** — lightweight REST API and dashboard server
- **SQLite** — zero-dependency persistent storage
- **Docker / Docker Compose** — one-command deployment
- **Vanilla JS** — dashboard with no build step required

---

