FROM python:3.6-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
  wget \
  unzip \
  libgomp1 \
  && rm -rf /var/lib/apt/lists/*

# Set the working directory
WORKDIR /app

# Copy and install Python dependencies
COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install -r requirements.txt

# No need to COPY app files — they're mounted via volume
CMD ["python", "main.py"]
