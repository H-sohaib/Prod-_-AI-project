FROM python:3.6-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
  wget \
  unzip \
  libgomp1 \
  && rm -rf /var/lib/apt/lists/*

# Upgrade pip just to avoid future issues
RUN pip install --upgrade pip

# Install Python dependencies
RUN pip install \
  setuptools \
  flask \
  numpy \
  tensorflow==2.3 \
  joblib \
  pandas \
  lightgbm \
  scikit-learn \
  tqdm \
  lief==0.9.0

# Set the working directory inside the container
WORKDIR /app

# Copy your app files if needed
# COPY ./app /app

# Default command (override in docker-compose if needed)
# COPY ./app /app
# CMD ["python", "main.py"]