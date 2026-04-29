FROM python:3.11-slim

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY . .

# Train model on first build (optional: skip and mount pre-trained model)
RUN python train.py

# Expose Flask port
EXPOSE 5180

ENV FLASK_DEBUG=false
ENV PORT=5180

CMD ["gunicorn", "--bind", "0.0.0.0:5180", "--workers", "2", "--timeout", "60", "app:app"]
