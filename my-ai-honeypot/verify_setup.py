import os
import requests
import socket

def check_ollama():
    print("[*] Checking Ollama...")
    try:
        r = requests.get("http://localhost:11434/api/tags")
        if r.status_code == 200:
            models = [m['name'] for m in r.json().get('models', [])]
            print(f"[+] Ollama is online. Available models: {models}")
            if "llama3.2:latest" in models or "llama3.2" in models:
                print("[+] llama3.2 is ready.")
            else:
                print("[!] llama3.2 is NOT pulled. Run: ollama pull llama3.2")
        else:
            print("[!] Ollama returned error status.")
    except:
        print("[!] Ollama is NOT running or accessible at localhost:11434.")

def check_files():
    files = ["honeypot_local.py", "finetune_honeypot.py", "analyze_attacks.py", "app.py"]
    print("[*] Checking files...")
    for f in files:
        if os.path.exists(f):
            print(f"[+] Found {f}")
        else:
            print(f"[!] MISSING: {f}")

def check_port(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('localhost', port)) == 0

if __name__ == "__main__":
    print("--- HONEYPOT VERIFICATION ---")
    check_files()
    check_ollama()
    
    if check_port(2222):
        print("[!] Port 2222 is ALREADY in use. Make sure no other honeypot is running.")
    else:
        print("[+] Port 2222 is free.")
    print("--------------------------------")
