#!/bin/bash
# 🛡️ setup_security.sh - Network Isolation (v0.4)
# Limits outgoing traffic to prevent the honeypot from being used as a proxy.

# Flush existing rules
iptables -F

# 1. Allow Loopback (Internal communication between Python and Ollama)
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# 2. Allow established and related connections (important for return traffic)
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# 3. Allow Incoming SSH (Port 2222)
iptables -A INPUT -p tcp --dport 2222 -j ACCEPT

# 4. Allow outgoing DNS (required for updates/initial setup)
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT

# 5. Allow outgoing HTTP/HTTPS (Required for Ollama pull)
# Note: You can comment this out once the model is pulled for maximum isolation
iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT

# 6. DROP everything else (Egress Lockdown)
iptables -P OUTPUT DROP
iptables -P FORWARD DROP

echo "[+] Security rules applied. Outbound traffic restricted."
