#!/usr/bin/env python3
"""
🧠 AI Honeypot Fine-Tuner (Professional Version)
Fine-tunes Qwen 2.5 1.5B to simulate a vulnerable Linux server.
Optimized for Blackwell (RTX 50xx) GPUs and Python 3.13.
"""

import os
import json
import torch
from datasets import load_dataset, Dataset
from transformers import (
    AutoModelForCausalLM, 
    AutoTokenizer, 
    TrainingArguments, 
    BitsAndBytesConfig
)
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
from trl import SFTTrainer, SFTConfig

# --- CONFIG ---
MODEL_ID    = "Qwen/Qwen2.5-1.5B-Instruct"
OUTPUT_DIR  = "./honeypot-model-checkpoint"
LOG_FILE    = "attacks.jsonl"
MAX_STEPS   = 300  # Optimized for ~5 epochs over the Linux command dataset
DATASET_PATH = "linux-commands-data/ds.json"

SYSTEM_PROMPT = """You are a Linux bash shell on a vulnerable Ubuntu 22.04 server.
Respond to commands with realistic raw terminal output only.
No explanations. No disclaimers. Output ONLY what a real shell would print."""

# --- 1. DATA PREPARATION ---
def prepare_data():
    examples = []
    
    # Load Public Dataset from local file
    print(f"[+] Loading dataset from {DATASET_PATH}...")
    try:
        if os.path.exists(DATASET_PATH):
            with open(DATASET_PATH, 'r', encoding='utf-8') as f:
                raw_data = json.load(f)
                for row in raw_data:
                    examples.append({
                        "instruction": row.get("command", row.get("input", "")),
                        "output": row.get("output", row.get("response", ""))
                    })
        else:
            print("[-] Local dataset not found, attempting remote load...")
            remote_ds = load_dataset("mrheinen/linux-commands", split="train")
            for row in remote_ds:
                examples.append({
                    "instruction": row.get("command", row.get("input", "")),
                    "output": row.get("output", row.get("response", ""))
                })
    except Exception as e:
        print(f"[-] Could not load dataset: {e}")

    # Load Local Logs if present
    if os.path.exists(LOG_FILE):
        print(f"[+] Loading logs from {LOG_FILE}...")
        with open(LOG_FILE, 'r') as f:
            for line in f:
                try:
                    data = json.loads(line)
                    if data.get("event") == "command":
                        examples.append({
                            "instruction": data["command"],
                            "output": data.get("response", "Simulated output for " + data["command"])
                        })
                except: continue

    # Format for ChatML
    def format_chat(ex):
        return {"text": f"<|im_start|>system\n{SYSTEM_PROMPT}<|im_end|>\n<|im_start|>user\n{ex['instruction']}<|im_end|>\n<|im_start|>assistant\n{ex['output']}<|im_end|>"}

    print(f"[+] Prepared {len(examples)} training examples.")
    return Dataset.from_list([format_chat(e) for e in examples if e.get("instruction")])

# --- 2. MODEL LOADING ---
def load_llm():
    print(f"[+] Loading {MODEL_ID} in 4-bit (NF4) for Blackwell support...")
    
    bnb_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.bfloat16, # Use bfloat16 for better precision on newer NVIDIA cards
        bnb_4bit_use_double_quant=True,
    )

    tokenizer = AutoTokenizer.from_pretrained(MODEL_ID)
    tokenizer.pad_token = tokenizer.eos_token
    tokenizer.padding_side = "right"

    model = AutoModelForCausalLM.from_pretrained(
        MODEL_ID,
        quantization_config=bnb_config,
        device_map="auto",
        trust_remote_code=True,
        torch_dtype=torch.bfloat16
    )
    
    model = prepare_model_for_kbit_training(model)
    
    lora_config = LoraConfig(
        r=16,
        lora_alpha=32,
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
        lora_dropout=0.05,
        bias="none",
        task_type="CAUSAL_LM"
    )
    
    model = get_peft_model(model, lora_config)
    model.print_trainable_parameters()
    return model, tokenizer

# --- 3. TRAINING ---
def main():
    dataset = prepare_data()
    model, tokenizer = load_llm()

    print("[+] Starting training script...")
    
    training_args = SFTConfig(
        output_dir=OUTPUT_DIR,
        max_steps=MAX_STEPS,
        per_device_train_batch_size=2, # Increased for 8GB VRAM with 1.5B model
        gradient_accumulation_steps=4,
        learning_rate=2e-4,
        bf16=True, # Improved performance on Blackwell
        logging_steps=10,
        save_strategy="steps",
        save_steps=100,
        dataset_text_field="text",
        max_length=512,
        report_to="none",
        optim="paged_adamw_32bit" # Stable optimizer for 4-bit training
    )

    trainer = SFTTrainer(
        model=model,
        train_dataset=dataset,
        args=training_args,
        processing_class=tokenizer,
    )

    trainer.train()
    
    print(f"[+] Saving LoRA adapter to {OUTPUT_DIR}")
    trainer.save_model(OUTPUT_DIR)
    tokenizer.save_pretrained(OUTPUT_DIR)
    
    print("\n" + "="*50)
    print("FINISH SUCCESSFUL!")
    print(f"1. Model saved to {OUTPUT_DIR}")
    print("2. Next: Use 'adapter_model.safetensors' in your Ollama Modelfile.")
    print("="*50)

if __name__ == "__main__":
    main()
