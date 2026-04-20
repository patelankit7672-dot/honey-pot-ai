#!/usr/bin/env python3
"""
🚀 AI Honeypot - Model Finalizer
Merges LoRA adapters into the base model and exports to GGUF format for Ollama.
Requires: unsloth, torch
"""

from unsloth import FastLanguageModel
import os

# --- CONFIG ---
LORA_PATH = "honeypot-model" # Where Step 2 saved the adapters
OUTPUT_NAME = "honeypot-v1"  # The name of the resulting GGUF file
QUANTIZATION = "q4_k_m"      # Recommended balance of speed/quality

def main():
    if not os.path.exists(LORA_PATH):
        print(f"[!] Error: LoRA adapter directory '{LORA_PATH}' not found.")
        print("[!] Please run finetune_honeypot.py first.")
        return

    print(f"[*] Loading LoRA adapter from {LORA_PATH}...")
    
    # 1. Load the model with its LoRA weights
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name = LORA_PATH, # Loads the base model + LoRA automatically
        max_seq_length = 2048,
        load_in_4bit = True,
    )

    print(f"[*] Merging weights and exporting to GGUF ({QUANTIZATION})...")
    print("[*] Note: This might take a few minutes and requires some CPU/RAM.")

    # 2. Save as GGUF
    # This automatically merges everything and runs the conversion
    model.save_pretrained_gguf(
        OUTPUT_NAME, 
        tokenizer, 
        quantization_method = QUANTIZATION
    )

    print("\n" + "="*50)
    print(f"🎉 SUCCESS! Model exported as: {OUTPUT_NAME}.Q4_K_M.gguf")
    print("="*50)
    print("\nNext Steps:")
    print(f"1. Run: ollama create honeypot-v1 -f Modelfile")
    print("2. Start Honeypot: python honeypot_local.py")
    print("="*50)

if __name__ == "__main__":
    main()
