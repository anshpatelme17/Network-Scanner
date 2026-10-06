FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /code

# Nmap for controlled asset-inventory scans (Step 2). No other security
# tools are installed. The container is NOT privileged and does not use
# host networking; localhost connect/version scans need neither.
RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY alembic ./alembic
COPY alembic.ini ./alembic.ini

# Step 31: run as an unprivileged account. The image needs no root at
# runtime: the app binds an unprivileged port, writes no files outside
# /code, and needs no capabilities. Nmap's setuid helper is only relevant
# for privileged scans, which this platform does not perform.
RUN groupadd --system --gid 10001 appuser \
    && useradd --system --uid 10001 --gid appuser --no-create-home --home-dir /code \
        --shell /usr/sbin/nologin appuser \
    && chown -R appuser:appuser /code
USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/v1/health', timeout=4)"

# Step 31: bounded uvicorn. --limit-concurrency sheds load rather than
# queueing it without limit; --timeout-keep-alive closes idle sockets.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", \
     "--limit-concurrency", "128", "--timeout-keep-alive", "15"]
