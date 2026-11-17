FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml .
COPY app ./app
RUN pip install --no-cache-dir . && useradd --create-home argos && mkdir -p /data && chown argos /data
USER argos
ENV ARGOS_DB=/data/argos.db
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
