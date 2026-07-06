FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py .

ENV FINDINGS_DB_DIR=/data

VOLUME ["/data"]

ENTRYPOINT ["python", "-u", "server.py"]
