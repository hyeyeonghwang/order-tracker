FROM python:3.13-slim

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl nodejs npm \
    && npm install -g @openai/codex \
    && npm cache clean --force \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY entrypoint.sh .

ENV INCIDENT_DATA_DIR=/data/incidents \
    WORKSPACE_PATH=/workspace \
    PYTHONUNBUFFERED=1

EXPOSE 8001

HEALTHCHECK --interval=10s --timeout=3s --retries=5 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8001/healthz', timeout=2)"

ENTRYPOINT ["sh", "/app/entrypoint.sh"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8001"]
