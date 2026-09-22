# Multi-stage build for smaller image
FROM python:3.12-slim AS builder

WORKDIR /app
RUN pip install --no-cache-dir --upgrade pip setuptools wheel

COPY pyproject.toml requirements.txt README.md ./
COPY aws/ ./aws/
COPY iam_audit/ ./iam_audit/
COPY main.py ./
RUN pip install --no-cache-dir --user -r requirements.txt
RUN pip install --no-cache-dir --user .

# Production stage
FROM python:3.12-slim

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /root/.local /root/.local
ENV PATH=/root/.local/bin:$PATH

# Copy application code
COPY aws/ ./aws/
COPY iam_audit/ ./iam_audit/
COPY main.py ./

# Ensure Python can find modules
ENV PYTHONPATH=/app

EXPOSE 8000

# Default to API server; override with docker-compose or CLI
CMD ["uvicorn", "iam_audit.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
