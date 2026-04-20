import json
import os
import requests
import time
from pathlib import Path

# --- CONFIG ---
INPUT_FILE = "attacks.jsonl"
OUTPUT_FILE = "enriched_attacks.jsonl"
CACHE_FILE = "ip_cache.json"

def load_cache():
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, "r") as f:
            return json.load(f)
    return {}

def save_cache(cache):
    with open(CACHE_FILE, "w") as f:
        json.dump(cache, f)

def get_ip_info(ip, cache):
    if ip in cache:
        return cache[ip]
    
    if ip == "127.0.0.1" or ip.startswith("192.168."):
        return {"country": "Private", "city": "Local", "isp": "Internal"}

    try:
        print(f"[*] Looking up {ip}...")
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = r.json()
        if data['status'] == 'success':
            cache[ip] = {
                "country": data.get("country"),
                "city": data.get("city"),
                "isp": data.get("isp"),
                "lat": data.get("lat"),
                "lon": data.get("lon")
            }
            return cache[ip]
    except Exception as e:
        print(f"[!] Error looking up {ip}: {e}")
    
    return None

def main():
    print("[*] Performing Task 5: Geo-IP Enrichment...")
    if not os.path.exists(INPUT_FILE):
        print("[!] No logs found to enrich.")
        return

    cache = load_cache()
    enriched_count = 0
    
    with open(INPUT_FILE, "r") as fin, open(OUTPUT_FILE, "w") as fout:
        for line in fin:
            try:
                event = json.loads(line)
                ip = event.get("ip")
                if ip:
                    info = get_ip_info(ip, cache)
                    if info:
                        event["geo"] = info
                
                fout.write(json.dumps(event) + "\n")
                enriched_count += 1
            except: continue

    save_cache(cache)
    print(f"[+] Task Complete. Enriched {enriched_count} events. Saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
