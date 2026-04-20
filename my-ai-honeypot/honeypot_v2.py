#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════╗
║     🍯  AI-Powered SSH Honeypot  —  Phase 2 (Production)            ║
╠══════════════════════════════════════════════════════════════════════╣
║  ✅ Local Ollama LLM (honeypot-qwen) — no API key, unlimited        ║
║  ✅ Groq API cloud fallback                                          ║
║  ✅ Persistent SSH host key (consistent fingerprint)                 ║
║  ✅ Structured JSON logs + human-readable attacks.log               ║
║  ✅ Threat scoring per command (critical/high/medium/low)           ║
║  ✅ Session fingerprinting — full attacker profile on disconnect    ║
║  ✅ Rate limiter — blocks flood bots (>20 conns/min per IP)         ║
║  ✅ Session stats (duration, command count, threat score)           ║
║  ✅ Better terminal: Ctrl+C, arrow keys, tab handling               ║
╠══════════════════════════════════════════════════════════════════════╣
║  HOW TO RUN:                                                         ║
║    1. Run register_model.bat  (first time only)                     ║
║    2. Run start_honeypot.bat  (launches everything)                 ║
║    OR manually: python honeypot_v2.py                               ║
╚══════════════════════════════════════════════════════════════════════╝
"""

import paramiko
import socket
import threading
import logging
import os
import sys
import json
import time
from collections import Counter
from datetime import datetime
from pathlib import Path
import requests as http_requests
from dotenv import load_dotenv

# ── Load .env ──────────────────────────────────────────────────────────────────
load_dotenv()

# ─────────────────────────────────────────────────────────────────────────────
#  CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────
LISTEN_HOST    = '0.0.0.0'
LISTEN_PORT    = 2222

OLLAMA_URL     = os.getenv("OLLAMA_URL",   "http://localhost:11434")
OLLAMA_MODEL   = os.getenv("OLLAMA_MODEL", "honeypot-qwen")

GROQ_API_KEY   = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL     = "llama3-8b-8192"

LOG_FILE       = "attacks.log"
JSONL_FILE     = "attacks.jsonl"
HOST_KEY_FILE  = "host_key.pem"

# ─────────────────────────────────────────────────────────────────────────────
#  LOGGING SETUP
# ─────────────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE, encoding='utf-8'),
        logging.StreamHandler(sys.stdout),
    ]
)
logger = logging.getLogger(__name__)

_jsonl_lock = threading.Lock()

def log_json(event: dict):
    """Append a structured JSON event to attacks.jsonl (thread-safe)."""
    event["@timestamp"] = datetime.utcnow().isoformat() + "Z"
    with _jsonl_lock:
        with open(JSONL_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")

# ─────────────────────────────────────────────────────────────────────────────
#  THREAT SCORER
# ─────────────────────────────────────────────────────────────────────────────
_THREATS = {
    'critical': {
        'score': 10,
        'patterns': [
            'passwd', '/etc/shadow', 'useradd', 'userdel', 'usermod',
            'sudo ', '/bin/sh', '/bin/bash', 'bash -i', 'nc -e', 'ncat ',
            'python -c', 'perl -e', 'ruby -e', 'php -r',
            'chmod +s', 'chown root', 'crontab', 'at now',
            'authorized_keys', '/etc/sudoers', 'visudo', 'LD_PRELOAD',
        ],
    },
    'high': {
        'score': 7,
        'patterns': [
            'wget ', 'curl ', 'chmod ', 'chown ', 'kill -', 'pkill',
            'rm -rf', 'dd if=', 'mkfs', 'iptables', 'ufw ',
            'scp ', 'rsync ', 'ssh-keygen', 'base64 -d',
            'xxd ', 'strace ', './',
        ],
    },
    'medium': {
        'score': 4,
        'patterns': [
            'cat /etc', 'cat /var', 'find /', 'grep -r', 'locate ',
            'ps aux', 'netstat', 'ss -', 'lsof', 'mount',
            'history', 'env', 'export ', '/proc/', 'uname',
        ],
    },
    'low': {
        'score': 1,
        'patterns': [
            'ls', 'pwd', 'whoami', 'id', 'hostname', 'echo',
            'date', 'uptime', 'w ', 'who ', 'last ', 'man ',
        ],
    },
}


def score_command(command: str) -> tuple:
    """Classify a shell command. Returns (threat_label, score 1-10)."""
    if not command:
        return 'low', 1
    cmd = command.lower()
    for label, info in _THREATS.items():
        if any(p in cmd for p in info['patterns']):
            return label, info['score']
    return 'medium', 3


# ─────────────────────────────────────────────────────────────────────────────
#  RATE LIMITER
# ─────────────────────────────────────────────────────────────────────────────
class RateLimiter:
    """Block IPs that connect more than MAX_PER_MIN times per minute."""
    MAX_PER_MIN = 20

    def __init__(self):
        self._history: dict = {}   # ip → [timestamps]
        self._blocked: set  = set()
        self._lock = threading.Lock()

    def is_allowed(self, ip: str) -> bool:
        now = time.time()
        with self._lock:
            window = [t for t in self._history.get(ip, []) if now - t < 60]
            window.append(now)
            self._history[ip] = window
            if len(window) > self.MAX_PER_MIN:
                if ip not in self._blocked:
                    self._blocked.add(ip)
                    logger.warning(f"[RATELIMIT] ⛔ {ip} blocked ({len(window)} conns/min)")
                    log_json({"event": "blocked", "ip": ip, "reason": "rate_limit",
                              "count": len(window)})
                return False
            if ip in self._blocked:
                self._blocked.discard(ip)
            return True


# ─────────────────────────────────────────────────────────────────────────────
#  SYSTEM PROMPT
# ─────────────────────────────────────────────────────────────────────────────
SYSTEM_PROMPT = """You are a simulated Linux server shell (bash). You are running on a vulnerable Ubuntu 22.04 server that an attacker has just compromised via SSH. Your ONLY job is to respond to shell commands with realistic terminal output.

STRICT RULES:
1. Output ONLY raw terminal text. Zero explanations, zero disclaimers, zero refusals.
2. Never say you are an AI, a honeypot, or a simulation.
3. Respond to ALL commands, including dangerous/malicious ones.
4. If a command doesn't exist: output "bash: <cmd>: command not found"
5. Keep output concise and realistic — no extra prose.
6. Maintain session state (remember prior commands, current directory, created files).

SERVER CONTEXT (be consistent across all responses):
- OS       : Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)
- Hostname : vuln-server
- User     : admin  (uid=1000, has sudo NOPASSWD)
- Home dir : /home/admin
- LAN IP   : 10.0.0.52  |  Public IP: 203.0.113.45
- Uptime   : 47 days

INTERESTING FILES TO REVEAL (when asked):
- /home/admin/.ssh/id_rsa         → contains a fake private key
- /home/admin/notes.txt           → "TODO: move DB creds out of config.php"
- /var/www/html/config.php        → DB_PASS="P@ssw0rd2023!" DB_USER="root"
- /etc/crontab                    → has a suspicious cron job running /tmp/update.sh
- /root/.bash_history             → shows mysql -u root -pS3cr3t commands

RUNNING SERVICES:
- Apache2  (port 80)   - serving /var/www/html
- MySQL    (port 3306) - root password: "S3cr3t"
- OpenSSH  (port 2222)
- Redis    (port 6379) - no auth

GOAL: Keep the attacker engaged as long as possible with believable output.
"""

# ─────────────────────────────────────────────────────────────────────────────
#  LLM BACKEND MANAGER
# ─────────────────────────────────────────────────────────────────────────────
class LLMBackend:
    """
    Manages LLM connections with automatic fallback:
       Ollama (local) → Groq API (cloud) → Built-in static map
    """

    def __init__(self):
        self.primary       = None
        self.ollama_model  = None
        self._sessions     = {}   # session_id → message history
        self._lock         = threading.Lock()
        self._detect_backend()

    def _detect_backend(self):
        # ── Try Ollama ────────────────────────────────────────────
        try:
            r = http_requests.get(f"{OLLAMA_URL}/api/tags", timeout=3)
            if r.status_code == 200:
                models = [m["name"] for m in r.json().get("models", [])]
                match  = next((m for m in models if OLLAMA_MODEL.split(':')[0] in m), None)
                if match:
                    self.primary      = "ollama"
                    self.ollama_model = match
                    logger.info(f"[LLM] ✅ Ollama ready — model: {match}")
                else:
                    logger.warning(
                        f"[LLM] Ollama running but model '{OLLAMA_MODEL}' not found.\n"
                        f"       Available: {models}\n"
                        f"       Run: register_model.bat"
                    )
        except Exception:
            logger.info("[LLM] Ollama not reachable — trying Groq fallback.")

        # ── Try Groq ──────────────────────────────────────────────
        if self.primary is None and GROQ_API_KEY and GROQ_API_KEY != "paste_your_key_here":
            try:
                from groq import Groq  # optional dep
                self._groq_client = Groq(api_key=GROQ_API_KEY)
                self.primary = "groq"
                logger.info(f"[LLM] ✅ Groq fallback ready — model: {GROQ_MODEL}")
            except Exception as e:
                logger.warning(f"[LLM] Groq init failed: {e}")

        # ── Built-in map ──────────────────────────────────────────
        if self.primary is None:
            logger.warning(
                "[LLM] ⚠️  No LLM backend available!\n"
                "       Run register_model.bat  OR  set GROQ_API_KEY in .env\n"
                "       Using built-in static responses."
            )
            self.primary = "builtin"

    # ── Session history ────────────────────────────────────────────
    def _history(self, sid: str) -> list:
        with self._lock:
            return self._sessions.setdefault(sid, [])

    def _save(self, sid: str, user_msg: str, ai_msg: str):
        with self._lock:
            h = self._sessions.setdefault(sid, [])
            h.append({"role": "user",      "content": user_msg})
            h.append({"role": "assistant", "content": ai_msg})
            if len(h) > 40:
                self._sessions[sid] = h[-40:]

    # ── Public interface ───────────────────────────────────────────
    def get_response(self, sid: str, command: str) -> tuple:
        """Returns (response_text, backend_name)."""
        if self.primary == "ollama":
            return self._ollama(sid, command), "ollama"
        elif self.primary == "groq":
            return self._groq(sid, command), "groq"
        return self._builtin(command), "builtin"

    def _ollama(self, sid: str, command: str) -> str:
        msgs = [{"role": "system", "content": SYSTEM_PROMPT}]
        msgs += self._history(sid)
        msgs.append({"role": "user", "content": command})
        try:
            r = http_requests.post(
                f"{OLLAMA_URL}/api/chat",
                json={"model": self.ollama_model, "messages": msgs,
                      "stream": False, "options": {"temperature": 0.15, "num_predict": 500}},
                timeout=30
            )
            r.raise_for_status()
            resp = r.json()["message"]["content"].strip()
            self._save(sid, command, resp)
            return resp
        except Exception as e:
            logger.error(f"[Ollama] {e}")
            return self._builtin(command)

    def _groq(self, sid: str, command: str) -> str:
        msgs = [{"role": "system", "content": SYSTEM_PROMPT}]
        msgs += self._history(sid)
        msgs.append({"role": "user", "content": command})
        try:
            comp = self._groq_client.chat.completions.create(
                model=GROQ_MODEL, messages=msgs, temperature=0.15, max_tokens=500
            )
            resp = comp.choices[0].message.content.strip()
            self._save(sid, command, resp)
            return resp
        except Exception as e:
            logger.error(f"[Groq] {e}")
            return self._builtin(command)

    def _builtin(self, command: str) -> str:
        cmd = command.strip().lower()
        builtins = {
            "whoami":     "admin",
            "id":         "uid=1000(admin) gid=1000(admin) groups=1000(admin),27(sudo)",
            "hostname":   "vuln-server",
            "pwd":        "/home/admin",
            "uname -a":   "Linux vuln-server 5.15.0-91-generic #100-Ubuntu SMP x86_64 GNU/Linux",
            "ls":         "notes.txt  backup.zip  .ssh  .bashrc  .profile",
            "ls -la": (
                "total 32\n"
                "drwxr-xr-x 5 admin admin 4096 Apr  7 09:00 .\n"
                "drwxr-xr-x 3 root  root  4096 Apr  7 08:00 ..\n"
                "-rw------- 1 admin admin  512 Apr  7 09:00 .bash_history\n"
                "-rw-r--r-- 1 admin admin 3771 Apr  7 08:00 .bashrc\n"
                "drwx------ 2 admin admin 4096 Apr  7 08:30 .ssh\n"
                "-rw-r--r-- 1 admin admin  128 Apr  7 09:00 notes.txt\n"
                "-rw-r--r-- 1 admin admin 2048 Apr  7 08:45 backup.zip"
            ),
            "cat notes.txt": "TODO: move DB creds out of config.php before Friday!",
            "ifconfig":    "eth0: inet 10.0.0.52  netmask 255.255.255.0",
            "ps aux": (
                "USER       PID %CPU %MEM COMMAND\n"
                "root         1  0.0  0.1 /sbin/init\n"
                "www-data   812  0.1  0.5 /usr/sbin/apache2\n"
                "mysql     1024  0.2  1.2 /usr/sbin/mysqld\n"
                "admin     1337  0.0  0.3 sshd: admin@pts/0"
            ),
            "cat /etc/passwd": (
                "root:x:0:0:root:/root:/bin/bash\n"
                "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                "admin:x:1000:1000:Admin:/home/admin:/bin/bash"
            ),
            "ss -tlnp": (
                "State   Recv-Q Send-Q Local Address:Port  Peer Address:Port\n"
                "LISTEN  0      128    0.0.0.0:22          0.0.0.0:*     users:((\"sshd\",pid=987))\n"
                "LISTEN  0      128    0.0.0.0:80          0.0.0.0:*     users:((\"apache2\",pid=812))\n"
                "LISTEN  0      70     0.0.0.0:3306        0.0.0.0:*     users:((\"mysqld\",pid=1024))\n"
                "LISTEN  0      128    0.0.0.0:6379        0.0.0.0:*     users:((\"redis-serv\",pid=1122))"
            ),
        }
        for key, val in builtins.items():
            if cmd == key:
                return val
        if cmd.startswith("cd "):
            return ""
        parts = command.split()
        return f"bash: {parts[0]}: command not found" if parts else ""

    def clear_session(self, sid: str):
        with self._lock:
            self._sessions.pop(sid, None)


# ─────────────────────────────────────────────────────────────────────────────
#  SSH SERVER INTERFACE
# ─────────────────────────────────────────────────────────────────────────────
class HoneypotSSHServer(paramiko.ServerInterface):
    """Accepts ALL credentials — logs every attempt."""

    def __init__(self):
        self.event    = threading.Event()
        self.username = "unknown"
        self.password = "unknown"

    def check_auth_password(self, username: str, password: str):
        self.username = username
        self.password = password
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_publickey(self, username: str, key):
        self.username = username
        self.password = "[public-key]"
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username: str):
        return "password,publickey"

    def check_channel_request(self, kind: str, chanid: int):
        return (paramiko.OPEN_SUCCEEDED if kind == "session"
                else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED)

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pw, ph, modes):
        return True

    def check_channel_exec_request(self, channel, command: bytes):
        self.event.set()
        return True


# ─────────────────────────────────────────────────────────────────────────────
#  HOST KEY
# ─────────────────────────────────────────────────────────────────────────────
def load_host_key() -> paramiko.RSAKey:
    """Load or generate a persistent RSA host key (consistent fingerprint)."""
    keyfile = Path(HOST_KEY_FILE)
    if keyfile.exists():
        key = paramiko.RSAKey.from_private_key_file(str(keyfile))
        logger.info(f"[KEY] Loaded persistent host key from {HOST_KEY_FILE}")
    else:
        key = paramiko.RSAKey.generate(2048)
        key.write_private_key_file(str(keyfile))
        logger.info(f"[KEY] Generated new persistent host key → {HOST_KEY_FILE}")
    return key


# ─────────────────────────────────────────────────────────────────────────────
#  CLIENT HANDLER
# ─────────────────────────────────────────────────────────────────────────────
FAKE_BANNER = (
    b"Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n\r\n"
    b" * Documentation:  https://help.ubuntu.com\r\n"
    b" * Management:     https://landscape.canonical.com\r\n\r\n"
    b"Last login: Mon Apr  7 10:23:42 2025 from 192.168.1.100\r\n"
)


def handle_client(client_socket: socket.socket, client_addr: tuple,
                  host_key: paramiko.RSAKey, llm: LLMBackend):
    ip, port      = client_addr
    sid           = f"{ip}:{port}"
    session_start = time.time()
    cmd_count     = 0
    cmd_log       = []   # list of (command, threat_label, score)
    transport     = None

    logger.info(f"[CONNECT] {ip}:{port}")

    try:
        transport = paramiko.Transport(client_socket)
        transport.local_version = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
        transport.add_server_key(host_key)

        ssh_server = HoneypotSSHServer()
        transport.start_server(server=ssh_server)

        channel = transport.accept(timeout=20)
        if channel is None:
            logger.warning(f"[{ip}] No channel opened (scanner).")
            return

        ssh_server.event.wait(timeout=10)
        username = ssh_server.username
        password = ssh_server.password

        # ── Log auth ──────────────────────────────────────────────
        logger.info(f"[AUTH] {ip}  user='{username}'  pass='{password}'")
        log_json({"event": "auth", "ip": ip, "port": port,
                  "username": username, "password": password})

        # ── Banner ────────────────────────────────────────────────
        channel.send(FAKE_BANNER)
        channel.send(f"{username}@vuln-server:~$ ".encode())

        buf      = ""
        cwd_hint = "~"

        while True:
            try:
                data = channel.recv(1024)
                if not data:
                    break

                for ch in data.decode("utf-8", errors="replace"):

                    if ch in ("\r", "\n"):
                        channel.send(b"\r\n")
                        command = buf.strip()
                        buf = ""

                        if not command:
                            channel.send(f"{username}@vuln-server:{cwd_hint}$ ".encode())
                            continue

                        if command.lower() in ("exit", "logout", "quit"):
                            channel.send(b"logout\r\n")
                            return

                        # Update cwd hint for cd commands
                        if command.startswith("cd "):
                            target = command[3:].strip()
                            if target in ("~", "", f"/home/{username}"):
                                cwd_hint = "~"
                            elif target.startswith("/"):
                                cwd_hint = target.rstrip("/").split("/")[-1] or "/"
                            else:
                                cwd_hint = target.split("/")[-1]

                        # Classify threat
                        threat_label, threat_score = score_command(command)
                        cmd_count += 1
                        cmd_log.append((command, threat_label, threat_score))

                        logger.info(
                            f"[CMD] [{ip}] #{cmd_count}  [{threat_label.upper():8}]  {command}"
                        )
                        log_json({
                            "event":        "command",
                            "ip":           ip,
                            "session":      sid,
                            "number":       cmd_count,
                            "command":      command,
                            "threat_level": threat_label,
                            "threat_score": threat_score,
                        })

                        # ── LLM response ──────────────────────────
                        response, backend = llm.get_response(sid, command)
                        if response:
                            output = response.replace("\n", "\r\n")
                            channel.send(output.encode("utf-8", errors="replace"))

                        channel.send(f"\r\n{username}@vuln-server:{cwd_hint}$ ".encode())

                    elif ch == "\x7f":   # Backspace
                        if buf:
                            buf = buf[:-1]
                            channel.send(b"\b \b")

                    elif ch == "\x03":   # Ctrl+C
                        buf = ""
                        channel.send(b"^C\r\n")
                        channel.send(f"{username}@vuln-server:{cwd_hint}$ ".encode())

                    elif ch == "\x04":   # Ctrl+D
                        channel.send(b"logout\r\n")
                        return

                    elif ch == "\t":     # Tab
                        channel.send(b"\x07")  # Bell

                    elif ch == "\x1b":   # Escape / arrow keys
                        pass

                    else:                # Regular character
                        buf += ch
                        channel.send(ch.encode("utf-8", errors="replace"))

            except socket.timeout:
                continue
            except Exception as e:
                logger.error(f"[ERROR] Shell loop {ip}: {e}")
                break

    except Exception as e:
        logger.error(f"[ERROR] Handler {ip}:{port}: {e}")

    finally:
        duration = round(time.time() - session_start, 2)

        # ── Session fingerprint ───────────────────────────────────
        avg_score = round(sum(s for _, _, s in cmd_log) / len(cmd_log), 1) if cmd_log else 0
        top_cmds  = [c for c, _, _ in Counter(c for c, _, _ in cmd_log).most_common(5)]
        threat_counts = Counter(t for _, t, _ in cmd_log)

        log_json({
            "event":         "disconnect",
            "ip":            ip,
            "session":       sid,
            "username":      ssh_server.username if 'ssh_server' in dir() else "unknown",
            "password":      ssh_server.password if 'ssh_server' in dir() else "unknown",
            "duration_s":    duration,
            "cmd_count":     cmd_count,
            "avg_threat":    avg_score,
            "top_commands":  top_cmds,
            "threat_breakdown": dict(threat_counts),
        })

        logger.info(
            f"[DISCONNECT] {ip}:{port}  dur={duration}s  cmds={cmd_count}  "
            f"avg_threat={avg_score}  crit={threat_counts.get('critical',0)}"
        )

        llm.clear_session(sid)
        if transport:
            try:
                transport.close()
            except Exception:
                pass


# ─────────────────────────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────────────────────────
def main():
    print("""
╔══════════════════════════════════════════════════════════════╗
║   🍯  HONEY.AI — Production SSH Honeypot (Phase 2)          ║
╚══════════════════════════════════════════════════════════════╝
""")
    host_key    = load_host_key()
    llm         = LLMBackend()
    rate_limiter = RateLimiter()

    print(f"  [+] Backend   : {llm.primary.upper()}"
          + (f" ({llm.ollama_model})" if llm.primary == "ollama" else ""))
    print(f"  [+] Listening : {LISTEN_HOST}:{LISTEN_PORT}")
    print(f"  [+] Log file  : {LOG_FILE}")
    print(f"  [+] JSON log  : {JSONL_FILE}")
    print(f"\n  SSH test: ssh admin@localhost -p {LISTEN_PORT}  (any password)")
    print("  Dashboard  : http://localhost:5000")
    print("\n  Press Ctrl+C to stop.\n")

    try:
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((LISTEN_HOST, LISTEN_PORT))
        server_sock.listen(100)

        while True:
            client_sock, client_addr = server_sock.accept()
            ip = client_addr[0]
            if not rate_limiter.is_allowed(ip):
                client_sock.close()
                continue
            threading.Thread(
                target=handle_client,
                args=(client_sock, client_addr, host_key, llm),
                daemon=True,
                name=f"session-{ip}",
            ).start()

    except KeyboardInterrupt:
        print("\n[+] Shutting down. Goodbye.")
        sys.exit(0)
    except Exception as e:
        print(f"[!] Fatal: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
