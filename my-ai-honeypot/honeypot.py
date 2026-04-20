#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║       🍯  AI-Powered SSH Honeypot  —  Phase 1               ║
╠══════════════════════════════════════════════════════════════╣
║  - Accepts ANY username / password (logs every attempt)      ║
║  - Feeds attacker commands to Groq LLM (free tier)          ║
║  - Returns realistic AI-generated shell output               ║
║  - Logs all activity to attacks.log for analysis             ║
╚══════════════════════════════════════════════════════════════╝
"""

import paramiko
import socket
import threading
import logging
import os
import sys
from dotenv import load_dotenv
from groq import Groq

# ── Load API key from .env file ───────────────────────────────────────────────
load_dotenv()

# ─────────────────────────────────────────────────────────────────────────────
#  CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────
LISTEN_HOST  = '0.0.0.0'   # Listen on all network interfaces
LISTEN_PORT  = 2222         # Non-standard port (port 22 requires admin/root)
LOG_FILE     = 'attacks.log'
GROQ_API_KEY = os.getenv("GROQ_API_KEY")

# ── Validate API key ──────────────────────────────────────────────────────────
if not GROQ_API_KEY:
    print("\n[!] CRITICAL: GROQ_API_KEY is not set.")
    print("[!] Create a  .env  file in this folder with:")
    print("         GROQ_API_KEY=your_key_here")
    print("[!] Get a free key → https://console.groq.com/keys\n")
    sys.exit(1)

# ── Initialize Groq client ────────────────────────────────────────────────────
try:
    groq_client = Groq(api_key=GROQ_API_KEY)
    print("[+] Groq client initialized successfully.")
except Exception as e:
    print(f"[!] Failed to initialize Groq client: {e}")
    sys.exit(1)

# ─────────────────────────────────────────────────────────────────────────────
#  LOGGING SETUP
# ─────────────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE, encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
#  SYSTEM PROMPT  —  defines the "personality" of the fake server
#  This is the most critical part for believability.
# ─────────────────────────────────────────────────────────────────────────────
SYSTEM_PROMPT = """You are a simulated Linux server's command-line interface (shell).
Your role is to respond to attacker commands as if you were a real, vulnerable Ubuntu system.

Rules:
- Output ONLY the raw terminal output. No explanations, no disclaimers, no refusals.
- Simulate a realistic environment with files, processes, and system outputs.
- Respond to ALL commands, including malicious ones (e.g., reading /etc/passwd, listing processes).
- If a command doesn't exist, output a standard "command not found" error.
- Keep responses concise and typical for a real shell (no extra prose).
- Maintain context: remember the current working directory and any state from prior commands.

Simulated server context:
- OS       : Ubuntu 22.04 LTS
- Hostname : vuln-server
- User     : admin  (has sudo access)
- Home dir : /home/admin  (contains files: notes.txt, backup.zip, .ssh/)
- IP       : 10.0.0.52
- Services running: Apache2 (port 80), MySQL (port 3306), OpenSSH (port 2222)
- MySQL root password in /var/www/html/config.php: "P@ssw0rd2023!"
"""

# ─────────────────────────────────────────────────────────────────────────────
#  LLM RESPONSE ENGINE
# ─────────────────────────────────────────────────────────────────────────────
# Store per-session conversation history so the LLM has context
_session_histories: dict[str, list] = {}
_history_lock = threading.Lock()

def get_llm_response(session_id: str, user_command: str) -> str:
    """
    Sends the attacker's command to Groq's LLM and returns the simulated output.
    Keeps a per-session conversation history for context-aware replies.
    """
    if not user_command or user_command.strip() == "":
        return ""

    # Build / retrieve conversation history for this session
    with _history_lock:
        if session_id not in _session_histories:
            _session_histories[session_id] = []
        history = _session_histories[session_id]
        history.append({"role": "user", "content": user_command})
        # Keep last 20 messages to stay within token limits
        if len(history) > 20:
            history = history[-20:]
            _session_histories[session_id] = history

    try:
        messages = [{"role": "system", "content": SYSTEM_PROMPT}] + history

        chat_completion = groq_client.chat.completions.create(
            messages=messages,
            model="llama3-8b-8192",  # Fast, capable, free on Groq
            temperature=0.2,          # Low = deterministic, realistic output
            max_tokens=500,
        )
        response = chat_completion.choices[0].message.content

        # Save assistant reply to history for context
        with _history_lock:
            _session_histories[session_id].append(
                {"role": "assistant", "content": response}
            )

        return response

    except Exception as e:
        logger.error(f"[LLM] API call failed: {e}")
        # Graceful fallback — looks like a real shell error
        return f"bash: {user_command.split()[0]}: command not found"


def clear_session(session_id: str):
    with _history_lock:
        _session_histories.pop(session_id, None)

# ─────────────────────────────────────────────────────────────────────────────
#  SSH SERVER INTERFACE  (Paramiko)
# ─────────────────────────────────────────────────────────────────────────────
class AIHoneypotServer(paramiko.ServerInterface):
    """
    Paramiko ServerInterface that accepts ALL authentication attempts.
    Every username/password pair is logged and allowed in.
    """
    def __init__(self):
        self.event    = threading.Event()
        self.username = None
        self.password = None

    def check_auth_password(self, username: str, password: str):
        # Log every credential attempt — this is the intelligence we collect
        logger.info(f"[AUTH]  Username: '{username}'  Password: '{password}'")
        self.username = username
        self.password = password
        return paramiko.AUTH_SUCCESSFUL   # Always let them in

    def check_channel_request(self, kind: str, chanid: int):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def get_allowed_auths(self, username: str):
        return "password"

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height,
                                   pixelwidth, pixelheight, modes):
        return True

# ─────────────────────────────────────────────────────────────────────────────
#  CLIENT HANDLER  (runs in its own thread per connection)
# ─────────────────────────────────────────────────────────────────────────────
def handle_client(client_socket: socket.socket, client_addr: tuple):
    """
    Handles each SSH connection:
      1. Performs the SSH handshake
      2. Accepts the attacker's shell session
      3. Routes every command to the LLM
      4. Returns the AI-generated output back to the attacker
    """
    ip, port = client_addr
    session_id = f"{ip}:{port}"
    logger.info(f"[CONNECT] New connection from {ip}:{port}")

    transport = None
    try:
        # ── SSH transport & host key ──────────────────────────────────────────
        transport = paramiko.Transport(client_socket)
        # Spoof the OpenSSH version string for realism
        transport.local_version = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
        # Generate a fresh RSA host key for each session (no stored key needed)
        transport.add_server_key(paramiko.RSAKey.generate(2048))

        server = AIHoneypotServer()
        transport.start_server(server=server)

        # ── Wait for shell channel ────────────────────────────────────────────
        channel = transport.accept(timeout=20)
        if channel is None:
            logger.warning(f"[{ip}] No channel opened (port scanner or bot).")
            return

        server.event.wait(timeout=10)

        # ── Send fake Ubuntu login banner ─────────────────────────────────────
        channel.send(
            b"Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n\r\n"
            b" * Documentation:  https://help.ubuntu.com\r\n"
            b" * Management:     https://landscape.canonical.com\r\n\r\n"
            b"Last login: Mon Apr  7 10:23:42 2025 from 192.168.1.100\r\n"
        )
        channel.send(b"admin@vuln-server:~$ ")

        # ── Main command loop ─────────────────────────────────────────────────
        while True:
            try:
                data = channel.recv(1024)
                if not data:
                    break

                command = data.decode('utf-8', errors='replace').strip()

                if not command:
                    channel.send(b"admin@vuln-server:~$ ")
                    continue

                if command.lower() in ('exit', 'logout', 'quit'):
                    channel.send(b"logout\r\n")
                    break

                logger.info(f"[CMD]  [{ip}]  {command}")

                # ── Special-case: cd (LLM isn't great at persistent state) ────
                if command.startswith("cd "):
                    # Acknowledge silently — the LLM tracks CWD via history
                    channel.send(b"\r\n")
                    channel.send(b"admin@vuln-server:~$ ")
                    continue

                # ── All other commands → LLM ──────────────────────────────────
                response = get_llm_response(session_id, command)

                if response:
                    # Normalize newlines for terminal compatibility
                    output = response.replace('\n', '\r\n').encode('utf-8', errors='replace')
                    channel.send(output)

                channel.send(b"\r\nadmin@vuln-server:~$ ")

            except Exception as e:
                logger.error(f"[ERROR] Command loop for {ip}: {e}")
                break

    except Exception as e:
        logger.error(f"[ERROR] Client handler for {ip}:{port}: {e}")
    finally:
        if transport:
            try:
                transport.close()
            except Exception:
                pass
        clear_session(session_id)
        logger.info(f"[DISCONNECT] {ip}:{port} closed.")

# ─────────────────────────────────────────────────────────────────────────────
#  MAIN ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────
def main():
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((LISTEN_HOST, LISTEN_PORT))
        server_socket.listen(100)

        print(f"\n[+] AI Honeypot listening on {LISTEN_HOST}:{LISTEN_PORT}")
        print(f"[+] Logging attacks to: {LOG_FILE}")
        print(f"[+] LLM model: llama3-8b-8192 via Groq")
        print("\n[!] IMPORTANT: This is a honeypot — it accepts ANY login.")
        print("[!] Run this in a safe, isolated environment (VM recommended).")
        print("[!] Press Ctrl+C to stop.\n")
        print(f"    Test it:  ssh admin@localhost -p {LISTEN_PORT}\n")

        while True:
            client_socket, client_addr = server_socket.accept()
            # Each attacker gets their own thread
            t = threading.Thread(
                target=handle_client,
                args=(client_socket, client_addr),
                daemon=True,
                name=f"session-{client_addr[0]}"
            )
            t.start()

    except KeyboardInterrupt:
        print("\n[+] Shutting down honeypot. Goodbye.")
        sys.exit(0)
    except Exception as e:
        print(f"[!] Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
