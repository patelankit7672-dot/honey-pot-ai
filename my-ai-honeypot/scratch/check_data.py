import os
import json
from datasets import load_dataset
from huggingface_hub import login

# --- CONFIG ---
DATASET_NAME = "mrheinen/linux-commands"
SAVE_PATH = "linux-commands-data/ds.json"
os.makedirs("linux-commands-data", exist_ok=True)

def download_and_format():
    print(f"[+] Downloading dataset: {DATASET_NAME}...")
    try:
        # Pull from Hugging Face
        dataset = load_dataset(DATASET_NAME, split="train")
        print(f"[+] Downloaded {len(dataset)} examples.")
        
        # Format for our trainer
        formatted_data = []
        for row in dataset:
            # The dataset usually has 'instruction' and 'output' or 'command' and 'output'
            cmd = row.get("command", row.get("instruction", ""))
            out = row.get("output", row.get("response", ""))
            
            if cmd and out:
                formatted_data.append({
                    "command": cmd,
                    "output": out
                })
        
        # Save locally
        with open(SAVE_PATH, "w", encoding="utf-8") as f:
            json.dump(formatted_data, f, indent=2)
            
        print(f"[+] Successfully saved {len(formatted_data)} examples to {SAVE_PATH}")
        return True
        
    except Exception as e:
        print(f"[-] Error: {e}")
        return False

if __name__ == "__main__":
    download_and_format()
