#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════╗
║   🍯  HONEY.AI — Threat Intelligence Dashboard  v2.0                ║
╠══════════════════════════════════════════════════════════════════════╣
║  Features:                                                           ║
║  ✅ Real-time Geo-IP world map (Leaflet.js)                          ║
║  ✅ Threat severity scoring & animated gauges                        ║
║  ✅ Attacker fingerprint table (IP, creds, country, risk)            ║
║  ✅ Live command feed with color-coded threat badges                 ║
║  ✅ Attack timeline (24h) + hourly heatmap bars                      ║
║  ✅ Premium dark glassmorphism UI                                    ║
║  ✅ Auto-refreshes every 5 seconds                                   ║
╚══════════════════════════════════════════════════════════════════════╝

Run: python dashboard.py
Open: http://localhost:5000
"""

import json
import os
import pandas as pd
from flask import Flask, render_template_string, jsonify
from datetime import datetime, timedelta

# ── Config ─────────────────────────────────────────────────────────────────────
JSONL_FILE     = "attacks.jsonl"
ENRICHED_FILE  = "enriched_attacks.jsonl"

app = Flask(__name__)

# ── Threat classification ──────────────────────────────────────────────────────
_THREAT_MAP = {
    'critical': {
        'patterns': [
            'passwd', '/etc/shadow', 'useradd', 'userdel', 'usermod',
            'sudo ', '/bin/sh', '/bin/bash', 'bash -i', 'nc -e', 'ncat ',
            'python -c', 'perl -e', 'ruby -e', 'php -r',
            'chmod +s', 'chown root', 'crontab', 'at now',
            'authorized_keys', '/etc/sudoers', 'visudo',
        ],
        'score': 10, 'label': 'critical',
    },
    'high': {
        'patterns': [
            'wget ', 'curl ', 'chmod ', 'chown ', 'kill ', 'pkill',
            'rm -rf', 'dd if=', 'mkfs', 'iptables', 'ufw ',
            'scp ', 'rsync ', 'ssh-keygen', 'base64 -d',
            'xxd ', 'strings ', 'strace ', './',
        ],
        'score': 7, 'label': 'high',
    },
    'medium': {
        'patterns': [
            'cat /etc', 'cat /var', 'find /', 'grep -r', 'locate ',
            'ps aux', 'netstat', 'ss -', 'lsof', 'mount',
            'history', 'env', 'export ', '/proc/', 'uname',
        ],
        'score': 4, 'label': 'medium',
    },
    'low': {
        'patterns': [
            'ls', 'pwd', 'whoami', 'id', 'hostname', 'echo',
            'date', 'uptime', 'w ', 'who', 'last ', 'man ',
        ],
        'score': 1, 'label': 'low',
    },
}

def classify_command(command: str) -> tuple:
    """Returns (threat_label, score 1-10)."""
    if not command:
        return 'unknown', 0
    cmd = command.lower()
    for label, info in _THREAT_MAP.items():
        if any(p in cmd for p in info['patterns']):
            return info['label'], info['score']
    return 'medium', 3


# ── Data loader ────────────────────────────────────────────────────────────────
def load_events(prefer_enriched: bool = False) -> pd.DataFrame:
    """Load JSONL events. Falls back to raw if enriched not available."""
    fname = ENRICHED_FILE if (prefer_enriched and os.path.exists(ENRICHED_FILE)) else JSONL_FILE
    if not os.path.exists(fname):
        return pd.DataFrame()
    rows = []
    with open(fname, 'r', encoding='utf-8') as f:
        for line in f:
            try:
                rows.append(json.loads(line.strip()))
            except Exception:
                continue
    if not rows:
        return pd.DataFrame()
    df = pd.DataFrame(rows)
    if '@timestamp' in df.columns:
        df['@timestamp'] = pd.to_datetime(df['@timestamp'], utc=True, errors='coerce')
    return df


# ── API: Main stats ────────────────────────────────────────────────────────────
@app.route('/api/stats')
def api_stats():
    df = load_events()
    if df.empty:
        return jsonify({'empty': True})

    has_event = 'event' in df.columns
    cmds_df  = df[df['event'] == 'command'] if has_event else pd.DataFrame()
    auth_df  = df[df['event'] == 'auth']    if has_event else pd.DataFrame()

    total_cmds  = int(len(cmds_df))
    total_auths = int(len(auth_df))
    unique_ips  = int(df['ip'].nunique()) if 'ip' in df.columns else 0

    # Overall threat score (0-100)
    threat_score = 0.0
    if not cmds_df.empty and 'command' in cmds_df.columns:
        scores = cmds_df['command'].dropna().apply(lambda c: classify_command(str(c))[1])
        threat_score = round(float(scores.mean()) * 10, 1) if len(scores) else 0.0

    # Timeline — hourly events, last 24h
    timeline_labels, timeline_values = [], []
    try:
        ts_df = df.dropna(subset=['@timestamp'])
        if not ts_df.empty:
            tl = ts_df.set_index('@timestamp').resample('h').size().tail(24)
            timeline_labels = [t.strftime('%H:%M') for t in tl.index]
            timeline_values = [int(v) for v in tl.values]
    except Exception:
        pass

    # Heatmap — event count by hour-of-day (0-23)
    heatmap = [0] * 24
    try:
        ts_df = df.dropna(subset=['@timestamp'])
        for ts in ts_df['@timestamp']:
            heatmap[ts.hour] += 1
    except Exception:
        pass

    # Recent activity (last 25 events)
    recent = []
    try:
        sorted_df = df.sort_values('@timestamp', ascending=False).head(25)
        for _, row in sorted_df.iterrows():
            rec = {}
            for k, v in row.items():
                if isinstance(v, pd.Timestamp):
                    rec[k] = v.isoformat()
                elif isinstance(v, float) and str(v) == 'nan':
                    rec[k] = None
                else:
                    rec[k] = v
            cmd = rec.get('command', '')
            if cmd:
                level, score = classify_command(str(cmd))
                rec['threat_level'] = level
                rec['threat_score'] = score
            recent.append(rec)
    except Exception:
        pass

    # Top commands
    top_cmds = {}
    if not cmds_df.empty and 'command' in cmds_df.columns:
        top_cmds = {str(k): int(v) for k, v in
                    cmds_df['command'].value_counts().head(8).items()}

    # Top IPs
    top_ips = {}
    if 'ip' in df.columns:
        top_ips = {str(k): int(v) for k, v in
                   df['ip'].value_counts().head(5).items()}

    return jsonify({
        'total_commands': total_cmds,
        'total_auths':    total_auths,
        'unique_ips':     unique_ips,
        'threat_score':   threat_score,
        'timeline_labels': timeline_labels,
        'timeline_values': timeline_values,
        'heatmap':         heatmap,
        'recent_activity': recent,
        'top_commands':    top_cmds,
        'top_ips':         top_ips,
    })


# ── API: Map points ────────────────────────────────────────────────────────────
@app.route('/api/map')
def api_map():
    df = load_events(prefer_enriched=True)
    if df.empty or 'geo' not in df.columns or 'ip' not in df.columns:
        return jsonify([])

    points = []
    for ip, group in df.groupby('ip'):
        geo_vals = group['geo'].dropna()
        if geo_vals.empty:
            continue
        geo = geo_vals.iloc[0]
        if not isinstance(geo, dict) or 'lat' not in geo or 'lon' not in geo:
            continue
        try:
            cmds = group['command'].dropna().tolist() if 'command' in group.columns else []
            total_score = sum(classify_command(str(c))[1] for c in cmds)
            points.append({
                'ip':          str(ip),
                'lat':         float(geo['lat']),
                'lon':         float(geo['lon']),
                'country':     geo.get('country', 'Unknown'),
                'city':        geo.get('city', ''),
                'isp':         geo.get('isp', ''),
                'events':      int(len(group)),
                'threat_score': min(100, int(total_score)),
            })
        except Exception:
            continue
    return jsonify(points)


# ── API: Attacker fingerprints ─────────────────────────────────────────────────
@app.route('/api/fingerprints')
def api_fingerprints():
    df = load_events(prefer_enriched=True)
    if df.empty or 'ip' not in df.columns:
        return jsonify([])

    fingerprints = []
    has_event = 'event' in df.columns

    for ip, group in df.groupby('ip'):
        auth_rows = group[group['event'] == 'auth'] if has_event else pd.DataFrame()
        cmd_rows  = group[group['event'] == 'command'] if has_event else pd.DataFrame()

        username = '?'
        password = '?'
        if not auth_rows.empty:
            if 'username' in auth_rows.columns:
                username = str(auth_rows['username'].iloc[0])
            if 'password' in auth_rows.columns:
                password = str(auth_rows['password'].iloc[0])

        cmds = cmd_rows['command'].dropna().tolist() if ('command' in cmd_rows.columns and not cmd_rows.empty) else []
        threat_scores = [classify_command(str(c))[1] for c in cmds]
        avg_threat = round(sum(threat_scores) / len(threat_scores) * 10) if threat_scores else 0

        geo = {}
        if 'geo' in group.columns:
            geo_vals = group['geo'].dropna()
            if not geo_vals.empty and isinstance(geo_vals.iloc[0], dict):
                geo = geo_vals.iloc[0]

        top_cmd = ''
        if cmds:
            from collections import Counter
            most = Counter(cmds).most_common(1)
            top_cmd = most[0][0] if most else cmds[0]

        fingerprints.append({
            'ip':          str(ip),
            'username':    username,
            'password':    password,
            'cmd_count':   int(len(cmds)),
            'threat_score': int(avg_threat),
            'top_cmd':     str(top_cmd),
            'country':     geo.get('country', '?'),
            'isp':         geo.get('isp', '?'),
        })

    fingerprints.sort(key=lambda x: x['threat_score'], reverse=True)
    return jsonify(fingerprints[:12])


# ── Dashboard HTML ─────────────────────────────────────────────────────────────
DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🍯 HONEY.AI | Threat Intelligence Dashboard</title>
    <meta name="description" content="Real-time AI-powered SSH honeypot threat intelligence dashboard">
    <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css">
    <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        /* ── Root tokens ─────────────────────────────────────────── */
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

        body {
            background: var(--bg);
            color: var(--text);
            font-family: var(--sans);
            min-height: 100vh;
            overflow-x: hidden;
        }

        /* Dot-grid background */
        body::before {
            content: '';
            position: fixed; inset: 0;
            background-image:
                radial-gradient(rgba(0,229,255,0.06) 1px, transparent 1px);
            background-size: 32px 32px;
            pointer-events: none; z-index: 0;
        }
        /* Glow orbs */
        .orb {
            position: fixed; border-radius: 50%;
            filter: blur(80px); pointer-events: none; z-index: 0;
        }
        .orb-1 { width:500px; height:500px; top:-150px; left:-150px;
                 background: radial-gradient(circle, rgba(0,229,255,0.07), transparent 70%); }
        .orb-2 { width:400px; height:400px; bottom:-100px; right:-100px;
                 background: radial-gradient(circle, rgba(124,58,237,0.07), transparent 70%); }

        /* ── Layout ──────────────────────────────────────────────── */
        .wrap { max-width: 1680px; margin: 0 auto; padding: 20px 24px; position: relative; z-index: 1; }

        /* ── Glass card ──────────────────────────────────────────── */
        .glass {
            background: var(--card);
            backdrop-filter: blur(20px) saturate(1.4);
            -webkit-backdrop-filter: blur(20px) saturate(1.4);
            border: 1px solid var(--border);
            border-radius: 18px;
            padding: 22px 24px;
            transition: border-color 0.25s ease;
        }
        .glass:hover { border-color: var(--border-glow); }

        .card-label {
            font-size: 0.65rem; font-weight: 600;
            letter-spacing: 2px; text-transform: uppercase;
            color: var(--muted); margin-bottom: 14px;
            display: flex; align-items: center; gap: 8px;
        }
        .card-label::before {
            content: ''; display: inline-block;
            width: 3px; height: 11px;
            background: var(--accent); border-radius: 2px;
        }

        /* ── Header ──────────────────────────────────────────────── */
        header {
            display: flex; align-items: center;
            justify-content: space-between;
            margin-bottom: 22px;
            padding-bottom: 18px;
            border-bottom: 1px solid var(--border);
        }
        .logo { display: flex; align-items: center; gap: 14px; }
        .logo-icon { font-size: 2.2rem; filter: drop-shadow(0 0 14px rgba(0,229,255,0.5)); }
        .logo h1 {
            font-size: 1.55rem; font-weight: 700; letter-spacing: -0.5px;
            background: linear-gradient(130deg, #ffffff 30%, var(--accent));
            -webkit-background-clip: text; -webkit-text-fill-color: transparent;
            line-height: 1;
        }
        .logo p { font-size: 0.65rem; color: var(--muted); letter-spacing: 2px; text-transform: uppercase; margin-top: 4px; }

        .hdr-right { display: flex; align-items: center; gap: 20px; }
        #clock { font-family: var(--mono); font-size: 0.78rem; color: var(--muted); }

        .live-badge {
            display: flex; align-items: center; gap: 8px;
            padding: 7px 14px;
            background: rgba(0,255,136,0.07);
            border: 1px solid rgba(0,255,136,0.18);
            border-radius: 100px;
        }
        .live-dot {
            width: 7px; height: 7px; background: var(--success);
            border-radius: 50%; box-shadow: 0 0 8px var(--success);
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0%,100% { opacity:1; transform:scale(1); }
            50%      { opacity:0.5; transform:scale(0.75); }
        }
        .live-txt { font-size: 0.7rem; font-weight: 700; letter-spacing: 1.5px; color: var(--success); }

        /* ── Stat cards ──────────────────────────────────────────── */
        .stats-row {
            display: grid;
            grid-template-columns: repeat(4,1fr);
            gap: 16px; margin-bottom: 20px;
        }
        .stat {
            position: relative; overflow: hidden;
            padding: 20px 22px;
        }
        .stat::after {
            content: ''; position: absolute;
            top: -20px; right: -20px;
            width: 100px; height: 100px; border-radius: 50%;
            filter: blur(40px); opacity: 0.18; pointer-events: none;
        }
        .stat.s-blue::after  { background: var(--accent); }
        .stat.s-purple::after { background: var(--accent2); }
        .stat.s-red::after   { background: var(--danger); }
        .stat.s-green::after  { background: var(--success); }

        .stat-icon { font-size: 1.4rem; margin-bottom: 14px; }
        .stat-val {
            font-size: 2.75rem; font-weight: 700;
            font-family: var(--mono); line-height: 1; margin-bottom: 6px;
        }
        .s-blue .stat-val   { color: var(--accent);  text-shadow: 0 0 24px rgba(0,229,255,0.35); }
        .s-purple .stat-val { color: #a78bfa;         text-shadow: 0 0 24px rgba(124,58,237,0.35); }
        .s-red .stat-val    { color: var(--danger);   text-shadow: 0 0 24px rgba(255,45,85,0.35); }
        .s-green .stat-val  { color: var(--success);  text-shadow: 0 0 24px rgba(0,255,136,0.35); }
        .stat-lbl { font-size: 0.68rem; font-weight: 600; letter-spacing: 1.5px; text-transform: uppercase; color: var(--muted); }

        /* ── Main grid (3 cols) ──────────────────────────────────── */
        .main-grid {
            display: grid;
            grid-template-columns: 340px 1fr 320px;
            gap: 18px; margin-bottom: 18px;
        }

        /* Timeline chart */
        .chart-box { height: 190px; position: relative; }

        /* Hourly heatmap */
        .hmap-title { margin-top: 18px; }
        .hmap-bars { display: flex; gap: 3px; align-items: flex-end; height: 56px; margin-top: 8px; }
        .hbar {
            flex: 1; border-radius: 3px 3px 0 0;
            min-height: 4px; cursor: pointer;
            transition: opacity 0.2s;
        }
        .hbar:hover { opacity: 0.75; }
        .hmap-lbls { display: flex; gap: 3px; margin-top: 4px; }
        .hmap-lbl { flex: 1; text-align: center; font-size: 0.5rem; color: var(--muted); font-family: var(--mono); }

        /* ── Map ─────────────────────────────────────────────────── */
        #attack-map {
            height: 370px; border-radius: 12px; overflow: hidden;
        }
        .leaflet-container { background: #08091a !important; font-family: var(--sans) !important; }
        .map-legend { display: flex; gap: 14px; margin-top: 10px; font-size: 0.68rem; color: var(--muted); flex-wrap: wrap; }
        .map-legend span { display: flex; align-items: center; gap: 5px; }
        .legend-dot { width: 8px; height: 8px; border-radius: 50%; }
        #map-count { margin-left: auto; }

        /* ── Fingerprint table ───────────────────────────────────── */
        .fp-scroll { max-height: 380px; overflow-y: auto; overflow-x: auto; }
        .fp-scroll::-webkit-scrollbar { width: 3px; }
        .fp-scroll::-webkit-scrollbar-thumb { background: var(--border); border-radius: 2px; }
        table.fp { width: 100%; border-collapse: collapse; font-size: 0.75rem; }
        table.fp th {
            text-align: left; padding: 7px 8px;
            color: var(--muted); font-size: 0.6rem;
            letter-spacing: 1.5px; text-transform: uppercase;
            border-bottom: 1px solid var(--border);
            white-space: nowrap;
        }
        table.fp td {
            padding: 9px 8px;
            border-bottom: 1px solid rgba(255,255,255,0.025);
            font-family: var(--mono); font-size: 0.72rem;
            white-space: nowrap;
        }
        table.fp tr:hover td { background: rgba(255,255,255,0.018); }
        .risk-pill {
            display: inline-block; padding: 2px 7px; border-radius: 6px;
            font-size: 0.6rem; font-weight: 700; letter-spacing: 0.5px;
        }

        /* ── Bottom grid (2 cols) ────────────────────────────────── */
        .bot-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 18px; }

        /* Feed */
        .feed { max-height: 300px; overflow-y: auto; }
        .feed::-webkit-scrollbar { width: 3px; }
        .feed::-webkit-scrollbar-thumb { background: var(--border); border-radius: 2px; }
        .feed-row {
            display: grid; grid-template-columns: 62px 88px 1fr;
            gap: 10px; padding: 9px 10px;
            border-bottom: 1px solid rgba(255,255,255,0.025);
            align-items: center; transition: background 0.15s;
        }
        .feed-row:hover { background: rgba(255,255,255,0.018); }
        .feed-ts { font-family: var(--mono); font-size: 0.68rem; color: var(--muted); }
        .feed-cmd {
            font-family: var(--mono); font-size: 0.75rem;
            white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
        }
        .badge {
            display: inline-block; padding: 2px 7px; border-radius: 5px;
            font-size: 0.58rem; font-weight: 700; letter-spacing: 1px; text-transform: uppercase;
        }
        .b-critical { background: rgba(255,45,85, 0.15); color: var(--danger);  border: 1px solid rgba(255,45,85,0.25); }
        .b-high     { background: rgba(255,140,0, 0.15); color: var(--warning); border: 1px solid rgba(255,140,0,0.25); }
        .b-medium   { background: rgba(255,215,0, 0.12); color: var(--gold);    border: 1px solid rgba(255,215,0,0.2); }
        .b-low      { background: rgba(0,255,136,0.1);  color: var(--success); border: 1px solid rgba(0,255,136,0.2); }
        .b-auth     { background: rgba(124,58,237,0.15); color: #a78bfa;         border: 1px solid rgba(124,58,237,0.25); }
        .b-unknown  { background: rgba(255,255,255,0.05); color: var(--muted);  border: 1px solid var(--border); }

        /* Top commands */
        .cmd-list { list-style: none; }
        .cmd-row {
            display: flex; align-items: center; gap: 10px;
            padding: 9px 0; border-bottom: 1px solid rgba(255,255,255,0.025);
        }
        .cmd-txt { font-family: var(--mono); font-size: 0.75rem; flex: 1; min-width: 0; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .cmd-bar-bg { flex: 1.2; height: 3px; background: rgba(255,255,255,0.05); border-radius: 2px; }
        .cmd-bar-fill { height: 100%; background: linear-gradient(90deg, var(--accent2), var(--accent)); border-radius: 2px; transition: width 0.5s ease; }
        .cmd-count { font-family: var(--mono); font-size: 0.78rem; font-weight: 600; color: var(--accent); min-width: 22px; text-align: right; }

        /* ── Anims ───────────────────────────────────────────────── */
        @keyframes fadeUp {
            from { opacity: 0; transform: translateY(14px); }
            to   { opacity: 1; transform: translateY(0); }
        }
        .glass { animation: fadeUp 0.45s ease both; }
        .stats-row .glass:nth-child(1) { animation-delay: 0.04s; }
        .stats-row .glass:nth-child(2) { animation-delay: 0.08s; }
        .stats-row .glass:nth-child(3) { animation-delay: 0.12s; }
        .stats-row .glass:nth-child(4) { animation-delay: 0.16s; }

        /* ── Responsive ──────────────────────────────────────────── */
        @media (max-width: 1280px) {
            .main-grid { grid-template-columns: 1fr 1fr; }
        }
        @media (max-width: 900px) {
            .main-grid { grid-template-columns: 1fr; }
            .stats-row { grid-template-columns: 1fr 1fr; }
            .bot-grid  { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
<div class="orb orb-1"></div>
<div class="orb orb-2"></div>

<div class="wrap">

    <!-- ── Header ────────────────────────────────────────────────── -->
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
            <div class="live-badge">
                <div class="live-dot"></div>
                <span class="live-txt">Live</span>
            </div>
        </div>
    </header>

    <!-- ── Stats ─────────────────────────────────────────────────── -->
    <div class="stats-row">
        <div class="glass stat s-blue">
            <div class="stat-icon">⚡</div>
            <div class="stat-val" id="v-cmds">0</div>
            <div class="stat-lbl">Commands Captured</div>
        </div>
        <div class="glass stat s-purple">
            <div class="stat-icon">🔑</div>
            <div class="stat-val" id="v-auths">0</div>
            <div class="stat-lbl">Auth Attempts</div>
        </div>
        <div class="glass stat s-red">
            <div class="stat-icon">🌐</div>
            <div class="stat-val" id="v-ips">0</div>
            <div class="stat-lbl">Unique Threat IPs</div>
        </div>
        <div class="glass stat s-green">
            <div class="stat-icon">🛡️</div>
            <div class="stat-val" id="v-threat" style="color:var(--success)">0</div>
            <div class="stat-lbl">Threat Score / 100</div>
        </div>
    </div>

    <!-- ── Main grid ──────────────────────────────────────────────── -->
    <div class="main-grid">

        <!-- Left: Timeline + Heatmap -->
        <div class="glass" style="padding:20px;">
            <div class="card-label">Attack Timeline · 24h</div>
            <div class="chart-box">
                <canvas id="tlChart"></canvas>
            </div>
            <div class="hmap-title">
                <div class="card-label">Events by Hour of Day</div>
            </div>
            <div class="hmap-bars" id="hmap-bars"><!-- JS --></div>
            <div class="hmap-lbls" id="hmap-lbls"><!-- JS --></div>
        </div>

        <!-- Center: World Map -->
        <div class="glass" style="padding:16px;">
            <div class="card-label">Global Attack Origin Map</div>
            <div id="attack-map"></div>
            <div class="map-legend">
                <span><div class="legend-dot" style="background:var(--danger)"></div> Critical</span>
                <span><div class="legend-dot" style="background:var(--warning)"></div> High</span>
                <span><div class="legend-dot" style="background:var(--accent)"></div> Low/Med</span>
                <span id="map-count">0 sources</span>
            </div>
        </div>

        <!-- Right: Fingerprints -->
        <div class="glass" style="padding:16px;">
            <div class="card-label">Attacker Fingerprints</div>
            <div class="fp-scroll">
                <table class="fp">
                    <thead>
                        <tr>
                            <th>IP</th>
                            <th>Creds</th>
                            <th>Cmds</th>
                            <th>Risk</th>
                            <th>Geo</th>
                        </tr>
                    </thead>
                    <tbody id="fp-body">
                        <tr><td colspan="5" style="color:var(--muted);padding:20px;text-align:center">Awaiting attackers…</td></tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- ── Bottom grid ────────────────────────────────────────────── -->
    <div class="bot-grid">

        <!-- Live Feed -->
        <div class="glass" style="padding:20px;">
            <div class="card-label">Real-time Activity Feed</div>
            <div class="feed" id="event-feed">
                <div style="color:var(--muted);padding:20px;text-align:center">Waiting for connections…</div>
            </div>
        </div>

        <!-- Top Commands -->
        <div class="glass" style="padding:20px;">
            <div class="card-label">Top Command Injections</div>
            <ul class="cmd-list" id="top-cmds">
                <li style="color:var(--muted);padding:20px;text-align:center">No commands yet…</li>
            </ul>
        </div>
    </div>

</div><!-- /wrap -->

<script>
// ── Clock ──────────────────────────────────────────────────────────────────────
function tick() {
    const t = new Date();
    document.getElementById('clock').textContent =
        t.toLocaleTimeString('en-GB',{hour12:false}) + ' (local)';
}
setInterval(tick, 1000); tick();

// ── Leaflet map ────────────────────────────────────────────────────────────────
const map = L.map('attack-map', {
    zoomControl: false, attributionControl: false,
    center: [20,0], zoom: 2, minZoom: 1, maxZoom: 8
});
L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
    subdomains: 'abcd', maxZoom: 19
}).addTo(map);

let mapLayers = [];
function renderMap(pts) {
    mapLayers.forEach(l => map.removeLayer(l));
    mapLayers = [];
    pts.forEach(p => {
        const s = p.threat_score || 0;
        const color  = s > 60 ? '#ff2d55' : s > 30 ? '#ff8c00' : '#00e5ff';
        const radius = Math.max(5, Math.min(20, 4 + p.events));
        const m = L.circleMarker([p.lat, p.lon], {
            radius, fillColor: color, color,
            fillOpacity: 0.55, weight: 1.5, opacity: 0.9
        }).bindPopup(
            `<div style="font-family:Space Grotesk,sans-serif;background:#0a0e1a;color:#e2e8f0;padding:6px 8px;border-radius:8px;font-size:12px;">` +
            `<b style="color:${color}">${p.ip}</b><br>` +
            `📍 ${p.city ? p.city+', ' : ''}${p.country}<br>` +
            `🏢 ${p.isp || 'Unknown ISP'}<br>` +
            `📊 ${p.events} events &nbsp;|&nbsp; Risk: ${s}` +
            `</div>`,
            {className:'',maxWidth:240}
        ).addTo(map);
        mapLayers.push(m);
    });
    document.getElementById('map-count').textContent = pts.length + ' sources';
}

// ── Timeline Chart ─────────────────────────────────────────────────────────────
const tlCtx = document.getElementById('tlChart').getContext('2d');
const tlChart = new Chart(tlCtx, {
    type: 'line',
    data: { labels: [], datasets: [{
        data: [], borderColor: '#00e5ff', borderWidth: 2.5,
        fill: true,
        backgroundColor: ctx => {
            const g = ctx.chart.ctx.createLinearGradient(0,0,0,180);
            g.addColorStop(0,'rgba(0,229,255,0.18)');
            g.addColorStop(1,'rgba(0,229,255,0)');
            return g;
        },
        tension: 0.4,
        pointBackgroundColor: '#00e5ff', pointRadius: 3, pointHoverRadius: 6,
    }]},
    options: {
        maintainAspectRatio: false,
        plugins: { legend: { display: false },
            tooltip: {
                backgroundColor: '#0c1020', borderColor: 'rgba(0,229,255,0.3)',
                borderWidth: 1, titleColor: '#00e5ff', bodyColor: '#e2e8f0',
            }
        },
        scales: {
            y: { beginAtZero: true, grid: { color: 'rgba(255,255,255,0.03)' }, ticks: { color: '#4a5568', font:{size:10} } },
            x: { grid: { display: false }, ticks: { color: '#4a5568', font:{size:10}, maxTicksLimit: 8 } }
        }
    }
});

// ── Heatmap bars ───────────────────────────────────────────────────────────────
function renderHeatmap(data) {
    const mx = Math.max(...data, 1);
    document.getElementById('hmap-bars').innerHTML = data.map((v,i) => {
        const pct = Math.round((v/mx)*100);
        const col = pct > 70 ? '#ff2d55' : pct > 40 ? '#ff8c00' : 'rgba(0,229,255,0.3)';
        return `<div class="hbar" style="height:${Math.max(pct,4)}%;background:${col}" title="${i}:00 — ${v}"></div>`;
    }).join('');
    document.getElementById('hmap-lbls').innerHTML = data.map((_,i) =>
        `<div class="hmap-lbl">${i%6===0?i+'h':''}</div>`
    ).join('');
}

// ── Fingerprint table ──────────────────────────────────────────────────────────
function riskPill(score) {
    if (score >= 70) return `<span class="risk-pill" style="background:rgba(255,45,85,0.15);color:#ff2d55;border:1px solid rgba(255,45,85,0.25)">${score}</span>`;
    if (score >= 40) return `<span class="risk-pill" style="background:rgba(255,140,0,0.15);color:#ff8c00;border:1px solid rgba(255,140,0,0.25)">${score}</span>`;
    if (score >= 15) return `<span class="risk-pill" style="background:rgba(255,215,0,0.12);color:#ffd700;border:1px solid rgba(255,215,0,0.2)">${score}</span>`;
    return `<span class="risk-pill" style="background:rgba(0,255,136,0.1);color:#00ff88;border:1px solid rgba(0,255,136,0.18)">${score}</span>`;
}
function renderFP(fps) {
    const tbody = document.getElementById('fp-body');
    if (!fps || !fps.length) {
        tbody.innerHTML = `<tr><td colspan="5" style="color:var(--muted);padding:20px;text-align:center">No attackers yet.</td></tr>`;
        return;
    }
    tbody.innerHTML = fps.map(f => `<tr>
        <td style="color:var(--accent)">${f.ip}</td>
        <td style="color:#888;font-size:0.68rem">${f.username}:${f.password.length > 12 ? f.password.slice(0,12)+'…' : f.password}</td>
        <td>${f.cmd_count}</td>
        <td>${riskPill(f.threat_score)}</td>
        <td style="color:#888;font-size:0.68rem">${f.country || '?'}</td>
    </tr>`).join('');
}

// ── Feed ───────────────────────────────────────────────────────────────────────
function badgeCls(item) {
    if (item.event === 'auth')     return 'b-auth';
    const l = item.threat_level || '';
    return {critical:'b-critical',high:'b-high',medium:'b-medium',low:'b-low'}[l] || 'b-unknown';
}
function badgeTxt(item) {
    if (item.event === 'auth') return 'AUTH';
    return (item.threat_level || item.event || 'CMD').toUpperCase();
}
function renderFeed(items) {
    if (!items || !items.length) return;
    document.getElementById('event-feed').innerHTML = items.map(e => {
        const ts = e['@timestamp'] ? e['@timestamp'].split('T')[1].slice(0,8) : '--';
        const txt = e.command || e.username || 'event';
        return `<div class="feed-row">
            <span class="feed-ts">${ts}</span>
            <span><span class="badge ${badgeCls(e)}">${badgeTxt(e)}</span></span>
            <span class="feed-cmd" title="${txt}">${txt}</span>
        </div>`;
    }).join('');
}

// ── Top commands ───────────────────────────────────────────────────────────────
function renderCmds(obj) {
    const el = document.getElementById('top-cmds');
    const entries = Object.entries(obj || {});
    if (!entries.length) { el.innerHTML = `<li style="color:var(--muted);padding:20px;text-align:center">No commands yet.</li>`; return; }
    const mx = Math.max(...entries.map(e=>e[1]),1);
    el.innerHTML = entries.map(([cmd,cnt]) => {
        const pct = Math.round((cnt/mx)*100);
        return `<li class="cmd-row">
            <span class="cmd-txt" title="${cmd}">${cmd}</span>
            <div class="cmd-bar-bg"><div class="cmd-bar-fill" style="width:${pct}%"></div></div>
            <span class="cmd-count">${cnt}</span>
        </li>`;
    }).join('');
}

// ── Counter animation ──────────────────────────────────────────────────────────
function animTo(el, target) {
    const start = parseInt(el.textContent) || 0;
    if (start === target) return;
    const dur = 600, steps = 20, delay = dur/steps;
    let i = 0;
    const t = setInterval(() => {
        i++;
        el.textContent = Math.round(start + (target-start)*(i/steps));
        if (i >= steps) { el.textContent = target; clearInterval(t); }
    }, delay);
}
function threatCol(s) {
    if (s>=70) return 'var(--danger)';
    if (s>=40) return 'var(--warning)';
    if (s>=20) return 'var(--gold)';
    return 'var(--success)';
}

// ── Main refresh ───────────────────────────────────────────────────────────────
async function refresh() {
    try {
        const r = await fetch('/api/stats');
        const d = await r.json();
        if (d.empty) return;

        animTo(document.getElementById('v-cmds'),   d.total_commands);
        animTo(document.getElementById('v-auths'),  d.total_auths);
        animTo(document.getElementById('v-ips'),    d.unique_ips);
        const tv = document.getElementById('v-threat');
        animTo(tv, d.threat_score);
        tv.style.color = threatCol(d.threat_score);

        tlChart.data.labels = d.timeline_labels || [];
        tlChart.data.datasets[0].data = d.timeline_values || [];
        tlChart.update('none');

        if (d.heatmap) renderHeatmap(d.heatmap);
        renderFeed(d.recent_activity || []);
        renderCmds(d.top_commands || {});
    } catch(e) { console.warn('[stats]', e); }

    // Map & fingerprints (separate endpoints)
    try {
        const mr = await fetch('/api/map');
        renderMap(await mr.json());
    } catch(e) {}

    try {
        const fr = await fetch('/api/fingerprints');
        renderFP(await fr.json());
    } catch(e) {}
}

refresh();
setInterval(refresh, 5000);
</script>
</body>
</html>"""


@app.route('/')
def index():
    return render_template_string(DASHBOARD_HTML)


if __name__ == '__main__':
    print('\n  ╔══════════════════════════════════════════════════╗')
    print('  ║   🍯  HONEY.AI Dashboard v2 — Starting          ║')
    print('  ╠══════════════════════════════════════════════════╣')
    print('  ║   🌐  Open: http://localhost:5000                ║')
    print('  ╚══════════════════════════════════════════════════╝\n')
    app.run(host='0.0.0.0', port=5000, debug=False)
