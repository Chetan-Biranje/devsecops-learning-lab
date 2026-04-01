# ═══════════════════════════════════════════════════════
#  DevSecOps Learning Lab – Dockerfile
#  Multi-stage build with security hardening
# ═══════════════════════════════════════════════════════

# ── Stage 1: Build / dependency install ─────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

# Install only build deps
COPY app/requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir --prefix=/install -r requirements.txt


# ── Stage 2: Runtime (minimal attack surface) ───────────
FROM python:3.12-slim AS runtime

# Security: create non-root user
RUN groupadd -r appgroup && useradd -r -g appgroup -s /sbin/nologin appuser

# Copy installed packages from builder
COPY --from=builder /install /usr/local

WORKDIR /app

# Copy application source
COPY app/src/ .

# Set ownership
RUN chown -R appuser:appgroup /app

# Drop to non-root
USER appuser

# Security: expose only what's needed
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/health')"

# Use gunicorn in production (not Flask dev server)
ENV FLASK_DEBUG=false \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", \
     "--timeout", "60", "--access-logfile", "-", "app:app"]
