#!/usr/bin/env python3
"""
📊 AI Honeypot Intelligence Analyzer
Processes attack logs to find trends and zero-day command attempts.
Generates a summary report in JSON.
"""

import json
import pandas as pd
import os
from datetime import datetime

# --- CONFIG ---
JSONL_FILE = "attacks.jsonl"
REPORT_FILE = "attack_summary.json"

def detect_sequences(df):
    """Detect common attack chains (e.g., wget -> chmod -> execute)."""
    sequences = []
    if df.empty or 'session' not in df.columns: return sequences
    
    # Sort by timestamp
    df = df.sort_values('@timestamp')
    
    for session, group in df.groupby('session'):
        cmds = " ".join(group['command'].dropna().astype(str).tolist())
        # Detect Malware Download & Execute pattern
        if any(x in cmds for x in ["wget", "curl"]) and "chmod" in cmds and "./" in cmds:
            sequences.append({"session": session, "type": "Malware Chain", "commands": cmds})
        # Detect Recon pattern
        if "whoami" in cmds and "uname" in cmds and "ls" in cmds:
            sequences.append({"session": session, "type": "Reconnaissance", "commands": cmds})
            
    return sequences

def analyze():
    print("[*] Performing Task 3: Threat Intelligence Analysis...")
    if not os.path.exists(JSONL_FILE): return

    events = []
    with open(JSONL_FILE, "r") as f:
        for line in f:
            try: events.append(json.loads(line))
            except: continue
    
    df = pd.DataFrame(events)
    if df.empty: return

    # Sequence Detection
    df_cmds = df[df['event'] == 'command']
    sequences = detect_sequences(df_cmds)

    # Basic Aggregations
    top_commands = df_cmds['command'].value_counts().head(10).to_dict()
    ips = df['ip'].nunique()

    report = {
        "timestamp": datetime.now().isoformat(),
        "total_commands": len(df_cmds),
        "unique_ips": ips,
        "attack_sequences": sequences,
        "top_commands": top_commands
    }

    with open(REPORT_FILE, "w") as f:
        json.dump(report, f, indent=4)

    print(f"[*] Intelligence Report Saved. Sequences found: {len(sequences)}")

if __name__ == "__main__":
    analyze()
