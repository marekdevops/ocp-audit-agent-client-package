FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    AUDIT_DATA_DIR=/data \
    AUDIT_DB_PATH=/data/audit.db \
    AUDIT_REPORT_DIR=/data/reports

WORKDIR /app
COPY pyproject.toml ./
COPY app ./app
COPY app/postgres-entrypoint.sh ./postgres-entrypoint.sh
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      fontconfig \
      libpango-1.0-0 \
      libpangoft2-1.0-0 \
      libjpeg62-turbo \
      libopenjp2-7 \
      libnss-wrapper \
      postgresql && \
    useradd --uid 1001 --gid 0 --home-dir /app --no-create-home --shell /usr/sbin/nologin audit && \
    rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir .

RUN mkdir -p /data/reports /var/lib/postgresql && chmod +x /app/postgres-entrypoint.sh && chown -R 1001:0 /data /var/lib/postgresql && chmod -R g=u /data /app /var/lib/postgresql
USER audit
EXPOSE 8080
ENTRYPOINT ["ocp-audit-agent"]
