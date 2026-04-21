# 🍯 HONEY.AI — AI-Powered SSH Honeypot

<div align="center">

![HONEY.AI Logo](https://img.shields.io/badge/🍯_HONEY.AI-Threat_Intelligence-00e5ff?style=for-the-badge&labelColor=050508)
[![Live Demo](https://img.shields.io/badge/Live_Demo-Vercel-00e5ff?style=for-the-badge&logo=vercel&logoColor=white&labelColor=050508)](https://honey-pot-ai.vercel.app)
[![Python](https://img.shields.io/badge/Python-3.13-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Ollama](https://img.shields.io/badge/Ollama-Local_LLM-7c3aed?style=for-the-badge&labelColor=050508)](https://ollama.com)
[![License](https://img.shields.io/badge/License-MIT-00ff88?style=for-the-badge&labelColor=050508)](LICENSE)

**An AI-powered SSH honeypot that catches attackers and analyzes their behavior in real-time.**  
Powered by a custom fine-tuned Qwen 2.5 1.5B model running locally via Ollama.

</div>

---

## 💡 How It Works (The 2-Part System)

This project consists of two components that work together to provide both security and visibility:

| Component | Purpose | Location | Data Type |
|---|---|---|---|
| **Public Dashboard** | Portfolio / Live Demo | **Vercel** (Cloud) | **Simulated** (Showcase) |
| **Real Honeypot** | Actual Security Trap | **Your Computer** (Local) | **Real** (Actual Attacks) |

> [!TIP]
> Use the **Vercel link** to show off your work to others. Use the **Local scripts** to actually catch hackers on your own machine.

---

## 🎯 What It Does

HONEY.AI is a production-grade SSH honeypot that:

- **Lures attackers** by simulating a vulnerable Ubuntu 22.04 server on port 2222
- **Engages them** using a fine-tuned local LLM that responds like a real bash shell
- **Classifies threats** with a 4-level scoring system (Critical / High / Medium / Low)
- **Logs everything** — credentials, commands, session fingerprints — to structured JSONL
- **Visualizes attacks** on a real-time dashboard with a world map, live feed, and heatmap
- **Sends daily reports** via email with threat summaries

## 🏗️ Architecture

```
Attacker
   │
   ▼  SSH on port 2222
┌─────────────────────────────────────────────────────┐
│  honeypot_v2.py  (Paramiko SSH Server)              │
│  ├── RateLimiter     → blocks flood bots            │
│  ├── ThreatScorer    → classifies each command      │
│  ├── LLMBackend      → routes to best available LLM │
│  │   ├── Ollama      → honeypot-qwen (fine-tuned)   │
│  │   └── Groq API    → cloud fallback               │
│  └── Session logger  → attacks.jsonl + attacks.log  │
└─────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────┐
│  Intelligence Pipeline                              │
│  enrich_data.py   → Geo-IP enrichment (ip-api.com) │
│  analyze_attacks.py → Pattern & sequence detection │
│  daily_report.py  → HTML email report              │
└─────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────┐
│  dashboard.py  (Flask + Leaflet + Chart.js)         │
│  http://localhost:5000                              │
│  ├── World map with attack geo-points               │
│  ├── Attacker fingerprint table                    │
│  ├── Real-time command feed with threat badges      │
│  └── 24h timeline + hourly heatmap                 │
└─────────────────────────────────────────────────────┘
```

## 🤖 The AI Model

The LLM that powers the honeypot shell responses is a **custom fine-tuned Qwen 2.5 1.5B** model:

- **Base**: Qwen2.5-1.5B-Instruct
- **Fine-tuning**: 4-bit LoRA on curated Linux shell command/response pairs
- **Hardware**: NVIDIA RTX 5070 (Blackwell, CUDA 12.8)
- **Deployment**: Ollama with merged weights → `honeypot-qwen`

The model responds to shell commands with realistic terminal output, maintaining consistent server state across the entire session.

## 🚀 Quick Start

### Prerequisites
- Python 3.11+
- [Ollama](https://ollama.com/download) installed and running
- NVIDIA GPU (recommended) or CPU

### Installation

```bash
# Clone the repository
git clone https://github.com/patelankit7672-dot/honey-pot-ai.git
cd honey-pot-ai/my-ai-honeypot

# Create virtual environment
python -m venv .venv
.\.venv\Scripts\activate  # Windows
# source .venv/bin/activate  # Linux/macOS

# Install dependencies
pip install -r requirements.txt

# Register the custom AI model
register_model.bat  # Windows only

# Launch everything
start_honeypot.bat  # Opens 3 windows: Ollama + Honeypot + Dashboard
```

### Test it
```bash
# In a separate terminal — use ANY password
ssh admin@localhost -p 2222

# View the dashboard
open http://localhost:5000
```

## 📊 Dashboard Features

| Feature | Description |
|---------|-------------|
| 🌍 **World Map** | Real-time attack origin points with Geo-IP enrichment |
| 🛡️ **Threat Score** | Per-session risk score (0–100) based on command severity |
| 👤 **Fingerprints** | Per-IP attacker profile: credentials, command count, country |
| 📈 **Timeline** | 24-hour attack frequency chart |
| 🕐 **Heatmap** | Events by hour-of-day to spot attack patterns |
| ⚡ **Live Feed** | Real-time command stream with color-coded threat badges |

## 📁 Project Structure

```
my-ai-honeypot/
├── honeypot_v2.py          # Main SSH honeypot server
├── dashboard.py            # Real-time Flask dashboard (localhost)
├── enrich_data.py          # Geo-IP enrichment pipeline
├── analyze_attacks.py      # Threat intelligence analysis
├── daily_report.py         # HTML email daily report
├── finetune.py             # Model fine-tuning script
├── Modelfile               # Ollama model configuration
├── start_honeypot.bat      # 🚀 One-click launcher
├── register_model.bat      # Register custom model with Ollama
├── setup_windows_task.bat  # Auto-start on Windows login
└── enrich_and_report.bat   # Run the full intelligence pipeline

vercel-dashboard/           # Public demo (deployed to Vercel)
├── api/index.py            # Serverless Flask app
└── vercel.json             # Vercel routing config
```

## 🔒 Security Notes

- **Never expose port 2222 directly** without firewall rules — this is a research tool
- The honeypot accepts ALL credentials by design (that's the point)
- Attack logs (`attacks.jsonl`) are excluded from git as they contain real attacker IPs
- The host key (`host_key.pem`) is excluded from git (private key!)

## 🛠️ Tech Stack

| Component | Technology |
|-----------|-----------|
| SSH Server | [Paramiko](https://www.paramiko.org/) |
| Local LLM | [Ollama](https://ollama.com) + Qwen 2.5 1.5B (fine-tuned) |
| Fine-tuning | [PEFT](https://github.com/huggingface/peft) + [TRL](https://github.com/huggingface/trl) (4-bit LoRA) |
| Cloud LLM | [Groq API](https://groq.com) (fallback) |
| Dashboard | [Flask](https://flask.palletsprojects.com) + [Chart.js](https://chartjs.org) + [Leaflet.js](https://leafletjs.com) |
| Geo-IP | [ip-api.com](https://ip-api.com) (free tier) |
| Deployment | [Vercel](https://vercel.com) (demo) |

## 📄 License

MIT License — free to use, modify, and distribute.

---

<div align="center">
Built with 🍯 by <a href="https://github.com/patelankit7672-dot">Ankit Patel</a>
<br>
<sub>⭐ Star this repo if you find it useful!</sub>
</div>
