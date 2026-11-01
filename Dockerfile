# Multi-stage Dockerfile for IAM Auditor CLI
FROM python:3.12-slim AS builder

WORKDIR /build

RUN pip install --no-cache-dir --upgrade pip setuptools wheel

COPY pyproject.toml requirements.txt README.md ./
COPY aws/ ./aws/
COPY iam_audit/ ./iam_audit/
COPY demo.py ./

# Install application dependencies into prefix directory
RUN pip install --no-cache-dir --prefix=/install .[cli]

# Production Stage - Minimal Runtime
FROM python:3.12-slim AS runner

WORKDIR /app

# Copy installed Python packages from builder
COPY --from=builder /install /usr/local

# Copy application files for offline execution & demo
COPY aws/ ./aws/
COPY iam_audit/ ./iam_audit/
COPY demo.py ./

# Create unprivileged auditor user (UID 10001)
RUN useradd --create-home --uid 10001 auditor \
    && chown -R auditor:auditor /app

USER auditor

ENV PYTHONPATH=/app

ENTRYPOINT ["iam-audit"]
CMD ["--help"]
