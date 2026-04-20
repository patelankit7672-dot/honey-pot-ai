#!/usr/bin/env python3
"""
🧠 AI Honeypot Fine-Tuner (Unsloth Edition)
Trains Llama 3.2 3B or Qwen 2.5 3B to be a realistic Linux shell.
Optimized for NVIDIA GPUs (RTX 30/40/50 series).
"""

from unsloth import FastLanguageModel
import torch
import os
import json
from datasets import Dataset
from trl import SFTTrainer
from transformers import TrainingArguments

# --- CONFIG ---
MODEL_NAME = "unsloth/Llama-3.2-3B-Instruct" # Or "unsloth/Qwen2.5-3B-Instruct"
MAX_SEQ_LENGTH = 2048
OUTPUT_DIR = "honeypot-model"
LOG_FILE = "attacks.jsonl" # Captures from your honeypot

# 1. Load Model & Tokenizer
model, tokenizer = FastLanguageModel.from_pretrained(
    model_name = MODEL_NAME,
    max_seq_length = MAX_SEQ_LENGTH,
    load_in_4bit = True,
)

# 2. Add LoRA Adapters
model = FastLanguageModel.get_peft_model(
    model,
    r = 16,
    target_modules = ["q_proj", "k_proj", "v_proj", "o_proj",
                     "gate_proj", "up_proj", "down_proj",],
    lora_alpha = 16,
    lora_dropout = 0,
    bias = "none",
)

# 3. Prepare Dataset
def format_prompt(sample):
    return {
        "text": f"<|im_start|>system\nYou are a Linux bash shell. Respond with raw output.<|im_end|>\n"
                f"<|im_start|>user\n{sample['command']}<|im_end|>\n"
                f"<|im_start|>assistant\n{sample['output']}<|im_end|>"
    }

print("[+] Loading training data...")
# Load public linux-commands dataset (simulated)
training_data = [
    {"command": "ls -la", "output": "total 8\ndrwxr-xr-x 2 root root 4096 Apr 11 10:00 .\ndrwxr-xr-x 3 root root 4096 Apr 11 10:00 .."},
    {"command": "whoami", "output": "admin"},
    {"command": "cat /etc/passwd", "output": "root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000:admin:/home/admin:/bin/bash"},
]

# Merge with your actual captured logs if they exist
if os.path.exists(LOG_FILE):
    with open(LOG_FILE, "r") as f:
        for line in f:
            data = json.loads(line)
            if data.get("event") == "command":
                training_data.append({
                    "command": data["command"],
                    "output": "bash: command not found" # Placeholder or manually labeled
                })

dataset = Dataset.from_list([format_prompt(d) for d in training_data])

# 4. Train
trainer = SFTTrainer(
    model = model,
    train_dataset = dataset,
    dataset_text_field = "text",
    max_seq_length = MAX_SEQ_LENGTH,
    args = TrainingArguments(
        per_device_train_batch_size = 2,
        gradient_accumulation_steps = 4,
        warmup_steps = 5,
        max_steps = 60,
        learning_rate = 2e-4,
        fp16 = not torch.cuda.is_bf16_supported(),
        bf16 = torch.cuda.is_bf16_supported(),
        logging_steps = 1,
        output_dir = "outputs",
    ),
)

print("[+] Starting fine-tuning...")
trainer.train()

# 5. Save LoRA model
model.save_pretrained(OUTPUT_DIR)
tokenizer.save_pretrained(OUTPUT_DIR)
print(f"[!] Model saved to {OUTPUT_DIR}")
