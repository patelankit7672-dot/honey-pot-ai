#!/usr/bin/env python3
"""
🍯 AI-Powered SSH Honeypot (Local Edition)
- Uses local Ollama (Llama 3.2 3B) for inference.
- Fully offline, no API keys required.
- Logs attacks for analysis.
"""

import paramiko
import socket
import threading
import logging
import os
import sys
import json
import requests
from pathlib import Path
from datetime import datetime

# --- CONFIGURATION ---
LISTEN_HOST  = '0.0.0.0'
LISTEN_PORT  = 2222
OLLAMA_URL   = "http://localhost:11434"
OLLAMA_MODEL = "honeypot-v1"  # Custom fine-tuned Qwen 2.5 1.5B model
LOG_FILE     = "attacks.log"
JSONL_FILE   = "attacks.jsonl"
HOST_KEY_FILE = "host_key.pem"

# --- LOGGING ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE, encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

def log_event(event_data):
    """Logs to JSONL for easy machine parsing."""
    event_data["@timestamp"] = datetime.utcnow().isoformat() + "Z"
    with open(JSONL_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(event_data) + "\n")

def load_host_key():
    """Load or generate a persistent RSA host key."""
    keyfile = Path(HOST_KEY_FILE)
    if keyfile.exists():
        key = paramiko.RSAKey.from_private_key_file(str(keyfile))
        logger.info(f"[KEY] Loaded persistent host key from {HOST_KEY_FILE}")
    else:
        key = paramiko.RSAKey.generate(2048)
        key.write_private_key_file(str(keyfile))
        logger.info(f"[KEY] Generated new persistent host key → {HOST_KEY_FILE}")
    return key

# --- LLM INTERFACE ---
class OllamaEngine:
    def __init__(self, url, model):
        self.url = url
        self.model = model
        self.sessions = {} # For /api/generate, we manage history in a single string

    def get_response(self, session_id, command):
        # Initialize context if new session
        if session_id not in self.sessions:
            self.sessions[session_id] = "system: You are a vulnerable Ubuntu 22.04 server shell. Respond with raw terminal output only. No disclaimers.\n"
        
        # Build prompt: [Previous History] + [New User Command]
        prompt = self.sessions[session_id] + f"user: {command}\nassistant:"
        
        try:
            r = requests.post(f"{self.url}/api/generate", json={
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": 0.2, "stop": ["user:", "assistant:"]}
            }, timeout=30)
            r.raise_for_status()
            response = r.json()["response"].strip()
            
            # Store full exchange to maintain shell state/context
            self.sessions[session_id] += f"user: {command}\nassistant: {response}\n"
            
            # Keep history within reasonable token limits (trimming old lines)
            lines = self.sessions[session_id].split('\n')
            if len(lines) > 30:
                self.sessions[session_id] = "\n".join([lines[0]] + lines[-29:])
            
            return response
        except Exception as e:
            logger.error(f"[Ollama Error] {e}")
            return f"bash: {command.split()[0] if command else 'cmd'}: command not found"

# --- SSH SERVER ---
class HoneypotServer(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()

    def check_auth_password(self, username, password):
        logger.info(f"[AUTH] {username}:{password}")
        log_event({"event": "auth", "username": username, "password": password})
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == 'session' else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pw, ph, modes):
        return True

import time

def handle_client(client, addr, host_key, llm):
    ip, port = addr
    session_id = f"{ip}:{port}"
    session_start = time.time()
    cmd_count = 0
    logger.info(f"[CONNECT] {ip}")
    
    transport = paramiko.Transport(client)
    transport.local_version = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
    transport.add_server_key(host_key)
    server = HoneypotServer()
    transport.start_server(server=server)
    
    channel = transport.accept(20)
    if not channel: return
    server.event.wait(10)

    # Shell Banner
    channel.send(b"Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\nadmin@vuln-server:~$ ")

    buf = ""
    while True:
        try:
            data = channel.recv(1024)
            if not data: break
            
            char = data.decode('utf-8', errors='ignore')
            if char in ('\r', '\n'):
                channel.send(b"\r\n")
                cmd = buf.strip()
                buf = ""
                
                if cmd.lower() in ('exit', 'logout'): break
                if not cmd:
                    channel.send(b"admin@vuln-server:~$ ")
                    continue

                cmd_count += 1
                logger.info(f"[CMD] {ip}: {cmd}")
                log_event({"event": "command", "ip": ip, "command": cmd, "session": session_id})

                # Call Local LLM
                response = llm.get_response(session_id, cmd)
                channel.send(response.replace('\n', '\r\n').encode() + b"\r\n")
                channel.send(b"admin@vuln-server:~$ ")
            elif char == '\x7f': # Backspace
                if buf:
                    buf = buf[:-1]
                    channel.send(b"\b \b")
            elif char == '\x03': # Ctrl+C
                buf = ""
                channel.send(b"^C\r\nadmin@vuln-server:~$ ")
            else:
                buf += char
                channel.send(char.encode())
        except: break

    duration = round(time.time() - session_start, 2)
    log_event({"event": "disconnect", "ip": ip, "session": session_id, "duration_s": duration, "cmd_count": cmd_count})
    transport.close()
    logger.info(f"[DISCONNECT] {ip}")

def main():
    host_key = load_host_key()
    llm = OllamaEngine(OLLAMA_URL, OLLAMA_MODEL)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((LISTEN_HOST, LISTEN_PORT))
    sock.listen(100)
    
    print(f"[+] AI Honeypot (Fine-tuned) Running on {LISTEN_PORT}...")
    while True:
        client, addr = sock.accept()
        threading.Thread(target=handle_client, args=(client, addr, host_key, llm), daemon=True).start()

if __name__ == "__main__":
    main()
