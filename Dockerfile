FROM python:3.12-slim AS builder

WORKDIR /build
COPY requirements.txt .

RUN pip install --upgrade pip \
 && pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.12-slim AS runtime

RUN groupadd -r appuser && useradd -r -g appuser appuser

WORKDIR /app

COPY --from=builder /install /usr/local

COPY differential_engine.py .
COPY api_server.py .

USER appuser

ENV PORT=8080
EXPOSE 8080

CMD uvicorn api_server:app \
    --host 0.0.0.0 \
    --port $PORT \
    --workers 2 \
    --no-access-log \
    --timeout-keep-alive 30
