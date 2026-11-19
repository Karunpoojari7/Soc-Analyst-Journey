# PAYGUARD SOC - Container Definition
# Lightweight, hardened Python 3.11 environment for synthetic FinTech SOC simulation.

FROM python:3.11-slim

# Prevent Python from writing .pyc files and enable unbuffered logging
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PAYGUARD_ENVIRONMENT=synthetic-lab \
    PAYGUARD_ENFORCE_NETWORK_ISOLATION=true \
    PAYGUARD_SYNTHETIC_CURRENCY=INR

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY backend/requirements.txt ./backend/requirements.txt
RUN pip install --no-cache-dir -r ./backend/requirements.txt

# Copy application source code
COPY backend/ ./backend/
COPY evidence/ ./evidence/
COPY simulator/ ./simulator/
COPY frontend/ ./frontend/
COPY detections/ ./detections/

# Create evidence and database directories
RUN mkdir -p /app/evidence

# Initialize and seed synthetic SQLite database
RUN python -c "from backend.data.seed import seed_database; seed_database('/app/payguard_synthetic.db')"

# Expose internal API and SOC Dashboard port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Start Uvicorn ASGI server
CMD ["uvicorn", "backend.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
