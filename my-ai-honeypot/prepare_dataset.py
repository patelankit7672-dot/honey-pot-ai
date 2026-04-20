#!/usr/bin/env python3
"""
📦 AI Honeypot - Dataset Preparer (v0.3)
Downloads 'mrheinen/linux-commands' from Hugging Face and formats it for Unsloth fine-tuning.
"""

import os
import json
from datasets import load_dataset
from pathlib import Path

# --- CONFIG ---
DATASET_NAME = "mrheinen/linux-commands"
OUTPUT_FILE  = "linux-commands-formatted.jsonl"

def main():
    print(f"[*] Downloading dataset: {DATASET_NAME}...")
    try:
        # Load the dataset
        ds = load_dataset(DATASET_NAME, split="train")
        print(f"[+] Downloaded {len(ds)} examples.")
        
        formatted_count = 0
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            for row in ds:
                # Standardize fields: command (input) -> output (response)
                # Note: Field names may vary by version, we check common ones
                command = row.get("command", row.get("instruction", row.get("input", "")))
                output  = row.get("output", row.get("response", ""))
                
                if not command or not output:
                    continue
                
                # Format for ChatML-style training
                example = {
                    "text": f"system: You are a Linux shell.\nuser: {command}\nassistant: {output}"
                }
                f.write(json.dumps(example) + "\n")
                formatted_count += 1
        
        print(f"[+] Successfully saved {formatted_count} formatted examples to {OUTPUT_FILE}")
        print("[!] Ready for Step 2: Running finetune_honeypot.py")

    except Exception as e:
        print(f"[-] Error downloading dataset: {e}")

if __name__ == "__main__":
    main()
