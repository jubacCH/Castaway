FROM python:3.12-slim AS builder
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.12-slim
WORKDIR /app
RUN groupadd -r castaway && useradd -r -g castaway -d /app -s /sbin/nologin castaway
COPY --from=builder /install /usr/local
COPY . .
RUN chown -R castaway:castaway /app

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

USER castaway
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
