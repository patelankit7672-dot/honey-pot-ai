import torch
from peft import AutoPeftModelForCausalLM
from transformers import AutoTokenizer
import os

# Configuration
checkpoint_dir = "./honeypot-model-checkpoint"
output_dir = "./honeypot-merged"

print(f"Loading model and adapter from {checkpoint_dir}...")

# Load the model with the adapter
# Note: We use device_map="cpu" for the merge process to stay safe on VRAM, 
# then move it to the final state. 1.5B is small enough for CPU/GPU merge.
model = AutoPeftModelForCausalLM.from_pretrained(
    checkpoint_dir,
    device_map="auto",
    torch_dtype=torch.bfloat16,
)

# Load the tokenizer
tokenizer = AutoTokenizer.from_pretrained(checkpoint_dir)

print("Merging weights...")
# Merge the LoRA layers into the base model
merged_model = model.merge_and_unload()

print(f"Saving merged model to {output_dir}...")
# Create output directory if it doesn't exist
os.makedirs(output_dir, exist_ok=True)

# Save the merged model and tokenizer
merged_model.save_pretrained(output_dir, safe_serialization=True)
tokenizer.save_pretrained(output_dir)

print("Finalizing...")
# Create a dummy config just in case Ollama looks for it as a fallback
# (Though merged models don't need adapter_config.json)

print(f"Success! Merged model saved in {output_dir}")
