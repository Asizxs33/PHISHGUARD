FROM python:3.11-slim

WORKDIR /app

# Install system dependencies (gcc for builds, libzbar0 for pyzbar, libgl1/libglib for opencv)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libzbar0 \
    libgl1 \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better Docker cache
COPY requirements.txt .

# Install PyTorch CPU-only (much smaller, ~200MB vs ~2GB)
RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu

# Install remaining dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Install Playwright browsers and dependencies
RUN playwright install --with-deps chromium

# Copy application code
COPY . .

# Create models directory if it doesn't exist
RUN mkdir -p models

# Train models during build to ensure they exist
RUN python -m ml.train_model

# Expose port
EXPOSE 10000

# Start command - Render uses port 10000 by default
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "10000"]
