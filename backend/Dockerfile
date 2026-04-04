FROM python:3.12-slim AS builder
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.12-slim
WORKDIR /app

RUN groupadd -r castaway && useradd -r -g castaway -d /app -s /sbin/nologin castaway
COPY --from=builder /install /usr/local

# Playwright Chromium system deps + gosu for privilege drop
RUN apt-get update && apt-get install -y --no-install-recommends \
        gosu \
        libnss3 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 \
        libxkbcommon0 libxcomposite1 libxdamage1 libxrandr2 libgbm1 \
        libpango-1.0-0 libcairo2 libasound2 libxshmfence1 libxfixes3 \
        libx11-xcb1 libxcb1 libxext6 libx11-6 libxcb-dri3-0 \
        fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

ENV PLAYWRIGHT_BROWSERS_PATH=/app/.playwright
RUN playwright install chromium && chmod -R 755 /app/.playwright

COPY . .
RUN chown -R castaway:castaway /app && chmod +x /app/entrypoint.sh

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

# Run as root initially; entrypoint fixes /data perms then drops to castaway
ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
