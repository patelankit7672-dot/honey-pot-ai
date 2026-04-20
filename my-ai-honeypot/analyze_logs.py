#!/usr/bin/env python3
"""
📊 AI Honeypot Log Analyzer
Analyzes attacks.log and attacks.jsonl to extract:
- Top attacker commands.
- Top credentials (user/pass).
- Potential Zero-Day attempts (commands the LLM couldn't handle).
"""

import json
import pandas as pd
import os
from datetime import datetime
from pathlib import Path

# --- CONFIG ---
JSONL_FILE = "attacks.jsonl"
REPORT_DIR = Path("reports")

def ensure_dirs():
    REPORT_DIR.mkdir(exist_ok=True)

def parse_logs():
    if not os.path.exists(JSONL_FILE):
        return pd.DataFrame()
    
    events = []
    with open(JSONL_FILE, "r", encoding="utf-8") as f:
        for line in f:
            try:
                events.append(json.loads(line))
            except:
                continue
    return pd.DataFrame(events)

def generate_reports(df):
    ensure_dirs()
    if df.empty:
        print("[!] No data to analyze.")
        return

    # Convert timestamp to datetime objects
    df['@timestamp'] = pd.to_datetime(df['@timestamp'])

    # 1. Command Stats
    cmd_df = df[df['event'] == 'command']
    top_commands = cmd_df['command'].value_counts().head(20)

    # 2. Auth Stats
    auth_df = df[df['event'] == 'auth']
    top_users = auth_df['username'].value_counts().head(10)
    top_pass = auth_df['password'].value_counts().head(10)

    # 3. Session Stats
    disc_df = df[df['event'] == 'disconnect']
    avg_duration = disc_df['duration_s'].mean() if not disc_df.empty else 0

    # Save CSVs
    top_commands.to_csv(REPORT_DIR / "top_commands.csv")
    top_users.to_csv(REPORT_DIR / "top_users.csv")

    # JSON Summary
    summary = {
        "generated_at": datetime.now().isoformat(),
        "total_events": len(df),
        "total_commands": len(cmd_df),
        "total_auths": len(auth_df),
        "avg_session_duration": round(float(avg_duration), 2),
        "top_commands": top_commands.to_dict(),
        "top_users": top_users.to_dict()
    }
    
    with open(REPORT_DIR / "summary.json", "w") as f:
        json.dump(summary, f, indent=4)
    
    return summary

def main():
    print("[*] Performing Task 2: Log Sanitization & Analysis...")
    df = parse_logs()
    summary = generate_reports(df)
    if summary:
        print(f"[*] Summary generated. Total commands: {summary['total_commands']}")

if __name__ == "__main__":
    main()
