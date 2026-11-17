FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml .
RUN pip install --no-cache-dir "fastapi>=0.115" "uvicorn>=0.30" "websockets>=13" "httpx>=0.27"
COPY app ./app
RUN useradd --create-home argos && mkdir -p /data && chown argos /data
USER argos
ENV ARGOS_DB=/data/argos.db
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
