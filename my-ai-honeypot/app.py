#!/usr/bin/env python3
"""
🍯 HONEYPOT MONITOR
Premium Real-Time Dashboard for AI SSH Honeypot.
Displays attack stats, command frequency, and connection timelines.
"""

import json
import os
from datetime import datetime, timedelta
from collections import Counter, defaultdict
from flask import Flask, render_template_string, jsonify

app = Flask(__name__)

# --- CONFIG ---
JSONL_FILE = "attacks.jsonl"

def get_stats():
    if not os.path.exists(JSONL_FILE):
        return {"total_attacks": 0, "unique_ips": 0, "top_commands": [], "timeline": []}

    events = []
    with open(JSONL_FILE, "r") as f:
        for line in f:
            try: events.append(json.loads(line))
            except: continue

    commands = [e["command"] for e in events if e.get("event") == "command"]
    auths = [e for e in events if e.get("event") == "auth"]
    ips = set(e.get("ip", "unknown") for e in events)

    # Timeline calculation (last 12 hours)
    timeline = defaultdict(int)
    # Since we don't have precise timestamps in JSONL yet (added now), we'll mock or use index
    # Let's assume we add timestamps to honeypot_local.py or just use event count for now
    
    return {
        "total_attacks": len(commands),
        "total_auth": len(auths),
        "unique_ips": len(ips),
        "top_commands": Counter(commands).most_common(10),
        "recent_activity": events[-10:][::-1]
    }

@app.route("/")
def index():
    return render_template_string("""
<!DOCTYPE html>
<html>
<head>
    <title>🍯 HoneyPot AI | Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono&family=Outfit:wght@400;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg: #050505;
            --card: #111;
            --accent: #00ffcc;
            --text: #eee;
            --border: #222;
        }
        body { 
            background: var(--bg); color: var(--text); 
            font-family: 'Outfit', sans-serif; margin: 0; padding: 40px;
        }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 40px; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; }
        .card { 
            background: var(--card); border: 1px solid var(--border); 
            padding: 25px; border-radius: 16px; transition: 0.3s;
        }
        .card:hover { border-color: var(--accent); transform: translateY(-5px); }
        .stat-num { font-size: 3rem; font-weight: 700; color: var(--accent); margin: 10px 0; }
        .stat-label { color: #888; text-transform: uppercase; letter-spacing: 1px; font-size: 0.8rem; }
        .commands-list { margin-top: 20px; }
        .cmd-item { display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #222; font-family: 'JetBrains Mono'; }
        .cmd-count { color: var(--accent); }
        h1 { margin: 0; background: linear-gradient(90deg, #00ffcc, #0099ff); -webkit-background-clip: text; -webkit-text-fill-color: transparent; font-size: 2.5rem; }
        .live-tag { background: #ff0055; padding: 4px 12px; border-radius: 20px; font-size: 0.7rem; font-weight: bold; animation: pulse 2s infinite; }
        @keyframes pulse { 0% { opacity: 1; } 50% { opacity: 0.5; } 100% { opacity: 1; } }
    </style>
</head>
<body>
    <div class="header">
        <h1>HONEYPOT AI <span style="font-size: 1rem; vertical-align: middle;">v2.0</span></h1>
        <div class="live-tag">LIVE FEED</div>
    </div>
    <div class="grid">
        <div class="card">
            <div class="stat-num" id="total-attacks">0</div>
            <div class="stat-label">Total Commands</div>
        </div>
        <div class="card">
            <div class="stat-num" id="unique-ips">0</div>
            <div class="stat-label">Unique Attackers</div>
        </div>
        <div class="card">
            <div class="stat-num" id="total-auth">0</div>
            <div class="stat-label">Auth Attempts</div>
        </div>
    </div>
    <div style="margin-top: 40px;" class="grid">
        <div class="card" style="grid-column: span 2;">
            <h2>Top Tactical Commands</h2>
            <div id="commands-list" class="commands-list"></div>
        </div>
        <div class="card">
            <h2>Recent Hits</h2>
            <div id="recent-hits" style="font-size: 0.8rem;"></div>
        </div>
    </div>

    <script>
        async function updateDashboard() {
            const res = await fetch('/api/stats');
            const data = await res.json();
            
            document.getElementById('total-attacks').innerText = data.total_attacks;
            document.getElementById('unique-ips').innerText = data.unique_ips;
            document.getElementById('total-auth').innerText = data.total_auth;

            const list = document.getElementById('commands-list');
            list.innerHTML = data.top_commands.map(c => `
                <div class="cmd-item">
                    <span>$ ${c[0]}</span>
                    <span class="cmd-count">${c[1]}</span>
                </div>
            `).join('');

            const hits = document.getElementById('recent-hits');
            hits.innerHTML = data.recent_activity.map(a => `
                <div style="margin-bottom: 10px; color: #aaa;">
                    <span style="color: var(--accent)">[${a.event.toUpperCase()}]</span> ${a.ip || a.username} 
                    <br><span style="font-family: 'JetBrains Mono'; font-size: 0.7rem;">${a.command || a.password}</span>
                </div>
            `).join('');
        }
        setInterval(updateDashboard, 3000);
        updateDashboard();
    </script>
</body>
</html>
    """)

@app.route("/api/stats")
def api_stats():
    return jsonify(get_stats())

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
