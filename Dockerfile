# hikvision-ingest — the public endpoint the Hikvision terminal pushes to (ingest_server.py).
# One worker on purpose: the outbox forwarder is a thread inside it; threads serve the pushes.
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY hik_parser.py ingest_server.py ./
RUN useradd --system --uid 10001 ingest && mkdir -p /data && chown ingest /data
USER ingest
VOLUME ["/data"]
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2).status == 200 else 1)"
CMD ["gunicorn", "-w", "1", "--threads", "8", "-b", "0.0.0.0:8000", "--access-logfile", "-", "ingest_server:create_app()"]
