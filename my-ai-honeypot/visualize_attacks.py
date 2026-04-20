#!/usr/bin/env python3
"""
📊 AI Honeypot - Visualizer (v0.5)
Generates an interactive Plotly heatmap from attack logs.
X-axis: Hour of Day, Y-axis: Command Category, Z-axis: Count.
"""

import json
import pandas as pd
import plotly.express as px
import os
from datetime import datetime

# --- CONFIG ---
JSONL_FILE = "attacks.jsonl"
OUTPUT_HTML = "reports/attack_heatmap.html"

def generate_heatmap():
    if not os.path.exists(JSONL_FILE):
        print(f"[-] No logs found at {JSONL_FILE}")
        return

    events = []
    with open(JSONL_FILE, "r") as f:
        for line in f:
            try:
                data = json.loads(line)
                if data.get("event") == "command":
                    events.append({
                        "timestamp": data.get("@timestamp"),
                        "command": data.get("command", "").split()[0] # Group by base command
                    })
            except: continue

    if not events:
        print("[-] No command events to visualize.")
        return

    df = pd.DataFrame(events)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df['hour'] = df['timestamp'].dt.hour
    
    # Aggregate data: Count of commands per hour
    agg_df = df.groupby(['hour', 'command']).size().reset_index(name='count')
    
    # Pivot for Heatmap
    pivot_df = agg_df.pivot(index='command', columns='hour', values='count').fillna(0)

    # Generate Heatmap
    fig = px.imshow(
        pivot_df,
        labels=dict(x="Hour of Day", y="Basic Command", color="Frequency"),
        x=pivot_df.columns,
        y=pivot_df.index,
        title="🔥 Attacker Command Frequency by Hour",
        color_continuous_scale="Viridis",
        aspect="auto"
    )

    os.makedirs("reports", exist_ok=True)
    fig.write_html(OUTPUT_HTML)
    print(f"[+] Heatmap generated: {OUTPUT_HTML}")

if __name__ == "__main__":
    generate_heatmap()
