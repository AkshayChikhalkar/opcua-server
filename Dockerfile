FROM python:3.13-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && useradd --create-home --uid 1000 recorder \
    && mkdir -p /app/certs \
    && chown -R recorder:recorder /app

COPY record_all.py br_recorder.py ecu_client.py lynx_recorder.py br.local.example.json ./
COPY shelly/lynx_scan.js shelly/lynx_scan.js
RUN cp br.local.example.json br.local.json && chown -R recorder:recorder /app

USER recorder
ENV PYTHONUNBUFFERED=1

CMD ["python", "-u", "record_all.py"]
