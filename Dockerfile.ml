# SentinelHunt ML Engine — Multi-stage Docker Build
FROM python:3.11-slim as base

WORKDIR /app

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential gcc && \
    rm -rf /var/lib/apt/lists/*

# Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy ML and detection modules
COPY ml/ ./ml/
COPY detection_engine/ ./detection_engine/
COPY streaming/ ./streaming/
COPY threat_intel/ ./threat_intel/
COPY feature_engineering/ ./feature_engineering/
COPY explainability/ ./explainability/
COPY experiments/ ./experiments/
COPY analysis/ ./analysis/

# Create necessary directories
RUN mkdir -p logs feature_engineering/outputs ml/models threat_intel/data

# Default command: run training pipeline
CMD ["python", "-m", "ml.training_pipeline"]
