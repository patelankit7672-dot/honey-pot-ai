#!/bin/bash
# 🍯 entrypoint.sh - Services Orchestrator (v0.4)

# 1. Start Ollama in the background
echo "[*] Starting Ollama server..."
ollama serve &

# 2. Wait for Ollama to be ready
echo "[*] Waiting for Ollama service to stabilize..."
until curl -s http://localhost:11434/api/tags > /dev/null; do
  sleep 2
done

# 3. Pull the required model if not present
echo "[*] Ensuring model llama3.2:3b is available..."
ollama pull llama3.2:3b

# 4. Apply Network Security (optional if running with NET_ADMIN)
if [ -f "./setup_security.sh" ]; then
  echo "[*] Applying iptables security rules..."
  bash ./setup_security.sh
fi

# 5. Start the AI Honeypot
echo "[+] Launching AI-Powered SSH Honeypot..."
python3 honeypot_local.py
