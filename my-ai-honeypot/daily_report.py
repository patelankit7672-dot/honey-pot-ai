#!/usr/bin/env python3
"""
📧 HONEY.AI — Daily Intelligence Report (v2.0)

Reads the last 24h of attack logs, generates an HTML email report,
and sends it to the configured recipient.

Setup:
  1. Edit .env → set SMTP_EMAIL and SMTP_PASSWORD (Gmail App Password)
  2. Run manually: python daily_report.py
  3. OR schedule via: enrich_and_report.bat (runs after enrichment)

Gmail App Password guide:
  https://myaccount.google.com → Security → 2-Step Verification → App passwords
"""

import smtplib
import json
import os
from datetime import datetime, timedelta
from email.message import EmailMessage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from collections import Counter
from dotenv import load_dotenv

load_dotenv()

# ── Config (from .env) ────────────────────────────────────────────────────────
RECIPIENT_EMAIL = "patelankit7672@gmail.com"
SENDER_EMAIL    = os.getenv("SMTP_EMAIL",    "")
SMTP_PASSWORD   = os.getenv("SMTP_PASSWORD", "")
SMTP_SERVER     = "smtp.gmail.com"
SMTP_PORT       = 465

JSONL_FILE      = "attacks.jsonl"
HEATMAP_PATH    = "reports/attack_heatmap.html"

# ── Threat scorer (same as honeypot_v2) ──────────────────────────────────────
_LEVEL_SCORES = {'critical': 10, 'high': 7, 'medium': 4, 'low': 1}


def _gather_stats() -> dict:
    """Collect last 24h stats from attacks.jsonl."""
    now       = datetime.utcnow()
    yesterday = now - timedelta(days=1)

    stats = {
        "commands":     0,
        "auth_attempts": 0,
        "unique_ips":   set(),
        "top_commands": Counter(),
        "threat_levels": Counter(),
        "sessions":     0,
        "critical_count": 0,
    }

    if not os.path.exists(JSONL_FILE):
        return stats

    with open(JSONL_FILE, "r", encoding="utf-8") as f:
        for line in f:
            try:
                data = json.loads(line.strip())
                ts_raw = data.get("@timestamp", "")
                if ts_raw:
                    ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00").replace("+00:00", ""))
                    if ts < yesterday:
                        continue

                event = data.get("event", "")
                ip    = data.get("ip", "unknown")

                if event == "auth":
                    stats["auth_attempts"] += 1
                    stats["unique_ips"].add(ip)

                elif event == "command":
                    stats["commands"] += 1
                    stats["unique_ips"].add(ip)
                    cmd = data.get("command", "")
                    if cmd:
                        stats["top_commands"][cmd] += 1
                    level = data.get("threat_level", "medium")
                    stats["threat_levels"][level] += 1
                    if level == "critical":
                        stats["critical_count"] += 1

                elif event == "disconnect":
                    stats["sessions"] += 1

            except Exception:
                continue

    return stats


def _html_report(stats: dict, period_start: str, period_end: str) -> str:
    """Generate a rich HTML email body."""
    ip_count = len(stats["unique_ips"])
    top5 = stats["top_commands"].most_common(5)

    # Threat distribution rows
    threat_rows = ""
    for level in ("critical", "high", "medium", "low"):
        count = stats["threat_levels"].get(level, 0)
        colors = {
            "critical": "#ff2d55",
            "high":     "#ff8c00",
            "medium":   "#ffd700",
            "low":      "#00ff88",
        }
        col = colors.get(level, "#888")
        threat_rows += f"""
        <tr>
            <td style="padding:8px 12px;border-bottom:1px solid #1a1a2e;">
                <span style="color:{col};font-weight:bold;text-transform:uppercase">{level}</span>
            </td>
            <td style="padding:8px 12px;border-bottom:1px solid #1a1a2e;font-family:monospace;color:#00e5ff">{count}</td>
        </tr>"""

    # Top commands rows
    cmd_rows = ""
    for cmd, cnt in top5:
        short_cmd = cmd[:60] + "…" if len(cmd) > 60 else cmd
        cmd_rows += f"""
        <tr>
            <td style="padding:8px 12px;border-bottom:1px solid #1a1a2e;font-family:monospace;color:#e2e8f0">{short_cmd}</td>
            <td style="padding:8px 12px;border-bottom:1px solid #1a1a2e;font-family:monospace;color:#00e5ff;text-align:right">{cnt}</td>
        </tr>"""

    alert_color = "#ff2d55" if stats["critical_count"] > 0 else "#00ff88"
    alert_msg   = (f"⚠️  {stats['critical_count']} CRITICAL commands detected!"
                   if stats["critical_count"] > 0
                   else "✅  No critical commands detected in this period.")

    return f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body {{
            margin: 0; padding: 0;
            background: #050508;
            font-family: 'Segoe UI', Arial, sans-serif;
            color: #e2e8f0;
        }}
        .container {{
            max-width: 640px; margin: 0 auto; padding: 32px 16px;
        }}
        .header {{
            background: linear-gradient(135deg, #0a0a14, #0d0d20);
            border: 1px solid rgba(0,229,255,0.15);
            border-radius: 16px;
            padding: 32px;
            text-align: center;
            margin-bottom: 24px;
        }}
        h1 {{
            font-size: 2rem; font-weight: 800;
            background: linear-gradient(90deg, #ffffff, #00e5ff);
            -webkit-background-clip: text; -webkit-text-fill-color: transparent;
            margin: 0;
        }}
        .subtitle {{
            color: #4a5568; font-size: 0.8rem;
            letter-spacing: 2px; text-transform: uppercase;
            margin-top: 8px;
        }}
        .alert-banner {{
            background: rgba(255,45,85,0.08);
            border: 1px solid {alert_color}33;
            border-radius: 10px;
            padding: 14px 20px;
            margin-bottom: 20px;
            color: {alert_color};
            font-weight: 600;
            text-align: center;
        }}
        .stat-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 12px;
            margin-bottom: 24px;
        }}
        .stat-box {{
            background: rgba(255,255,255,0.03);
            border: 1px solid rgba(255,255,255,0.07);
            border-radius: 12px;
            padding: 18px 20px;
        }}
        .stat-val {{
            font-size: 2rem; font-weight: 800;
            color: #00e5ff; font-family: monospace;
            line-height: 1;
        }}
        .stat-lbl {{
            font-size: 0.68rem; font-weight: 600;
            letter-spacing: 1.5px; text-transform: uppercase;
            color: #4a5568; margin-top: 6px;
        }}
        .section {{
            background: rgba(255,255,255,0.02);
            border: 1px solid rgba(255,255,255,0.06);
            border-radius: 12px;
            margin-bottom: 20px;
            overflow: hidden;
        }}
        .section-title {{
            padding: 14px 20px;
            font-size: 0.7rem; font-weight: 700;
            letter-spacing: 2px; text-transform: uppercase;
            color: #4a5568;
            border-bottom: 1px solid rgba(255,255,255,0.06);
        }}
        table {{ width: 100%; border-collapse: collapse; }}
        .footer {{
            text-align: center; color: #2d3748;
            font-size: 0.7rem; padding-top: 24px;
        }}
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <div style="font-size:2.5rem;margin-bottom:12px">🍯</div>
        <h1>HONEY.AI</h1>
        <div class="subtitle">Daily Intelligence Report</div>
        <div style="margin-top:12px;font-size:0.75rem;color:#4a5568">
            {period_start} — {period_end} UTC
        </div>
    </div>

    <div class="alert-banner">{alert_msg}</div>

    <div class="stat-grid">
        <div class="stat-box">
            <div class="stat-val">{stats['commands']}</div>
            <div class="stat-lbl">Commands Captured</div>
        </div>
        <div class="stat-box">
            <div class="stat-val">{stats['auth_attempts']}</div>
            <div class="stat-lbl">Auth Attempts</div>
        </div>
        <div class="stat-box">
            <div class="stat-val">{ip_count}</div>
            <div class="stat-lbl">Unique Attacker IPs</div>
        </div>
        <div class="stat-box">
            <div class="stat-val" style="color:#ff2d55">{stats['critical_count']}</div>
            <div class="stat-lbl">Critical Commands</div>
        </div>
    </div>

    <div class="section">
        <div class="section-title">Threat Level Breakdown</div>
        <table>{threat_rows}</table>
    </div>

    <div class="section">
        <div class="section-title">Top 5 Commands</div>
        <table>
            <tr>
                <th style="padding:8px 12px;text-align:left;color:#4a5568;font-size:0.65rem;letter-spacing:1px;font-weight:600;border-bottom:1px solid #1a1a2e">COMMAND</th>
                <th style="padding:8px 12px;text-align:right;color:#4a5568;font-size:0.65rem;letter-spacing:1px;font-weight:600;border-bottom:1px solid #1a1a2e">COUNT</th>
            </tr>
            {cmd_rows if cmd_rows else '<tr><td colspan="2" style="padding:16px;color:#4a5568;text-align:center">No commands logged.</td></tr>'}
        </table>
    </div>

    <div class="footer">
        Generated by HONEY.AI · {datetime.utcnow().strftime('%Y-%m-%d %H:%M')} UTC<br>
        Your AI-Powered SSH Honeypot is watching. 🛡️
    </div>
</div>
</body>
</html>"""


def send_report():
    print("[*] Generating HONEY.AI daily intelligence report...")

    stats = _gather_stats()
    now   = datetime.utcnow()
    start = (now - timedelta(days=1)).strftime("%Y-%m-%d %H:%M")
    end   = now.strftime("%Y-%m-%d %H:%M")

    print(f"    Commands : {stats['commands']}")
    print(f"    Auth     : {stats['auth_attempts']}")
    print(f"    IPs      : {len(stats['unique_ips'])}")
    print(f"    Critical : {stats['critical_count']}")

    # ── Check SMTP config ─────────────────────────────────────────
    if not SENDER_EMAIL or not SMTP_PASSWORD:
        print("\n[!] SMTP not configured — skipping email send.")
        print("    Set SMTP_EMAIL and SMTP_PASSWORD in your .env file.")
        print("    (Gmail: use an App Password, not your main password)")
        # Save report locally anyway
        out_path = Path("reports")
        out_path.mkdir(exist_ok=True)
        html = _html_report(stats, start, end)
        report_file = out_path / f"report_{now.strftime('%Y%m%d')}.html"
        report_file.write_text(html, encoding="utf-8")
        print(f"[+] HTML report saved locally: {report_file}")
        return

    # ── Build email ───────────────────────────────────────────────
    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"🍯 HONEY.AI Daily Report — {now.strftime('%Y-%m-%d')} ({stats['commands']} cmds, {stats['critical_count']} critical)"
    msg["From"]    = SENDER_EMAIL
    msg["To"]      = RECIPIENT_EMAIL

    html_body = _html_report(stats, start, end)
    plain_body = (
        f"HONEY.AI Daily Report — {now.strftime('%Y-%m-%d')}\n"
        f"Period: {start} – {end} UTC\n\n"
        f"Commands Captured : {stats['commands']}\n"
        f"Auth Attempts     : {stats['auth_attempts']}\n"
        f"Unique IPs        : {len(stats['unique_ips'])}\n"
        f"Critical Commands : {stats['critical_count']}\n"
    )
    msg.attach(MIMEText(plain_body, "plain"))
    msg.attach(MIMEText(html_body, "html"))

    # Attach heatmap if it exists
    if os.path.exists(HEATMAP_PATH):
        with open(HEATMAP_PATH, "rb") as f:
            att = MIMEText(f.read().decode("utf-8"), "html")
            att.add_header("Content-Disposition", "attachment",
                           filename="attack_heatmap.html")
            msg.attach(att)

    # ── Send ──────────────────────────────────────────────────────
    try:
        with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as server:
            server.login(SENDER_EMAIL, SMTP_PASSWORD)
            server.send_message(msg)
        print(f"[+] Report sent to {RECIPIENT_EMAIL} ✅")
    except smtplib.SMTPAuthenticationError:
        print("[!] SMTP auth failed — check SMTP_EMAIL and SMTP_PASSWORD in .env")
        print("    Gmail requires an App Password: https://myaccount.google.com/apppasswords")
    except Exception as e:
        print(f"[!] Failed to send email: {e}")


if __name__ == "__main__":
    send_report()
