# --- STAGE 1: OLLAMA BUILDER ---
FROM ollama/ollama:latest as ollama-base

# Pre-pull the model during build (optional, but makes image heavy)
# RUN ollama serve & sleep 5 && ollama pull llama3.2:3b

# --- STAGE 2: PYTHON ENVIRONMENT ---
FROM python:3.10-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    iptables \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# Copy Ollama binary from Stage 1
COPY --from=ollama-base /usr/bin/ollama /usr/bin/ollama

# Install Python requirements
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy honeypot code
COPY . .

# Expose SSH port
EXPOSE 2222

# Entrypoint to start services
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
