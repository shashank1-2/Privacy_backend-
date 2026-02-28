FROM python:3.10-slim

# Set working directory
WORKDIR /app

# Install system dependencies needed by spaCy and Presidio
RUN apt-get update && apt-get install -y \
    build-essential \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first (for Docker cache optimization)
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Download spaCy English model (required by Presidio)
RUN python -m spacy download en_core_web_lg

# Copy all application code
COPY . .

# Expose port
EXPOSE 8000

# Start the FastAPI server
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]