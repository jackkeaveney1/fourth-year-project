FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

EXPOSE 8080

# `docker compose up --wait` only waits for this to pass — without it,
# compose considers the container "healthy" the instant it starts, even
# while Flask is still blocked in wait_for_db(), and agent tool calls
# race a service that isn't listening yet.
HEALTHCHECK --interval=2s --timeout=2s --start-period=30s --retries=15 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health', timeout=2)" || exit 1

CMD ["python", "app.py"]
