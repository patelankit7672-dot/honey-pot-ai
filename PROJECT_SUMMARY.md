# 🍯 HONEY.AI — Complete Project Summary

## 📖 Introduction
**HONEY.AI** is an advanced, AI-powered SSH honeypot designed to deceive, monitor, and analyze cyber attackers in real-time. By combining traditional cybersecurity "traps" with Large Language Models (LLMs), it creates a highly realistic simulation of a vulnerable Linux server that can engage attackers and capture their techniques.

---

## ⚙️ How It Works (The Core Engine)

### 1. The SSH Sinkhole
The project uses the **Paramiko** library to create an SSH server listening on port **2222**. It accepts "connections" from any username/password combination, tricking the attacker into believing they have successfully bypassed security.

### 2. The AI "Shadow" Backend
Once inside, the "server" is not a real Linux OS. It is a shell controlled by an **LLM (Qwen-2.5-1.5B)**. 
- **Local Mode:** Uses **Ollama** to run the model locally on your hardware.
- **Cloud Mode:** If local hardware is unavailable, it uses the **Groq API** to generate responses in milliseconds.
- **Persistence:** The AI maintains a "session state," so if an attacker creates a folder, the AI "remembers" it and shows it when they type `ls` again.

### 3. Telemetry & Data Capture
Every interaction is logged into a structured **JSONL (Json Lines)** format:
- **Auth Attempts:** Captures IPs, Usernames, and Passwords.
- **Commands:** Every single command and the resulting AI output is saved.
- **Geographic Data:** The system uses Geo-IP lookups to identify the attacker's ISP, City, and Country.

---

## 🌟 Key Features

### 📊 Real-Time Threat Intelligence Dashboard
The custom-built Flask dashboard provides a premium, dark-mode interface with:
- **Interactive Global Map:** Visualizes attack origins in real-time using Leaflet.js.
- **Threat Scoring System:** Categorizes attacks into "Low," "Medium," "High," or "Critical" based on command complexity and risk (e.g., malware downloads).
- **At-a-Glance Metrics:** One-click navigation to see total commands, auth attempts, and unique threat actors.

### 🌓 Dual-Deployment Model
- **Real-Time Monitoring (Local):** Your local dashboard (`localhost:5000`) displays the real, live data captured by your machine.
- **Public Portfolio (Vercel):** A hosted version available at [honey-pot-ai.vercel.app](https://honey-pot-ai.vercel.app) showcases your UI design and capabilities to potential employers or peers using simulated activity.

### 🛡️ Security & Anonymity
- **Sandboxed Execution:** The attacker never has access to your actual files. The environment is 100% simulated by the AI.
- **Host Key Persistence:** The honeypot generates a unique RSA host key to maintain a consistent "fingerprint" for returning attackers.

---

## 🛠️ Technology Stack
- **Languages:** Python (Core Engine), HTML5/CSS3 (Dashboard).
- **Frameworks:** Flask (Web API), Paramiko (SSH Logic), Pandas (Data Analysis).
- **AI/ML:** Ollama, Groq Cloud API, Qwen-2.5-1.5B (Fine-tuned).
- **Frontend Tools:** Leaflet.js (Maps), Chart.js (Analytics), Google Space Grotesk (Typography).
- **Deployment:** Vercel (Serverless Dashboard), GitHub (Version Control).

---

## 📜 Next Steps & Usage
To run the system, simply execute:
```bash
start_honeypot.bat
```
This automates the environment setup, starts the AI server, initializes the SSH trap, and launches the monitoring dashboard.

**HONEY.AI — Turning Cyber Attacks into Intelligence.** 🛡️✨
