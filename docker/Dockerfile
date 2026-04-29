# ═══════════════════════════════════════════════════════
#  DevSecOps Learning Lab – Dockerfile
#  Multi-stage build with security hardening
# ═══════════════════════════════════════════════════════

# ── Stage 1: Build / dependency install ─────────────────
FROM python:3.12.3-slim AS builder

WORKDIR /build

# Copy and install dependencies
COPY app/requirements.txt .

RUN pip install --no-cache-dir --upgrade pip setuptools \
    && pip install --no-cache-dir --prefix=/install -r requirements.txt


# ── Stage 2: Runtime (minimal attack surface) ───────────
FROM python:3.12.3-slim AS runtime

LABEL maintainer="DevSecOps Learning Lab"
LABEL description="Secure Flask application for DevSecOps learning"
LABEL version="2.0"

# ── Security: create non-root user ──────────────────────
RUN groupadd -r appgroup && useradd -r -g appgroup -s /sbin/nologin appuser

# ── Copy installed packages from builder ────────────────
COPY --from=builder /install /usr/local

WORKDIR /app

# ── Copy application source ─────────────────────────────
COPY app/src/ .

# ── Set file ownership ──────────────────────────────────
RUN chown -R appuser:appgroup /app && chmod -R 755 /app

# ── Drop to non-root user ──────────────────────────────
USER appuser

# ── Expose only what's needed ────────────────────────────
EXPOSE 5000

# ── Security: Health check ──────────────────────────────
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/health')" || exit 1

# ── Environment variables ────────────────────────────────
ENV FLASK_DEBUG=false \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=random

# ── Use gunicorn in production (not Flask dev server) ────
CMD ["gunicorn", \
     "--bind", "0.0.0.0:5000", \
     "--workers", "4", \
     "--worker-class", "sync", \
     "--timeout", "60", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "--log-level", "info", \
     "--max-requests", "1000", \
     "--max-requests-jitter", "100", \
     "app:app"]
