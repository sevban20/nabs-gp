"""Bölüm 11: Observability — request-ID'li JSON structured logging ve
Prometheus metrikleri.

Prometheus: prometheus-fastapi-instrumentator kuruluysa /metrics açılır;
değilse uygulama metriksiz ama sorunsuz çalışır. Celery/Redis/Postgres
exporter'ları docker-compose.observability.yml içindedir.
"""
import json
import logging
import sys
import time
import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key in ("request_id", "path", "method", "status_code", "duration_ms"):
            if hasattr(record, key):
                entry[key] = getattr(record, key)
        if record.exc_info:
            entry["exc"] = self.formatException(record.exc_info)
        return json.dumps(entry, ensure_ascii=False)


def configure_json_logging() -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(logging.INFO)


class RequestIdMiddleware(BaseHTTPMiddleware):
    """API -> Celery -> git commit korelasyonu için request ID üretir;
    yanıt başlığına ve access loguna yazar."""

    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get("x-request-id", uuid.uuid4().hex[:16])
        request.state.request_id = request_id
        start = time.perf_counter()
        response = await call_next(request)
        duration_ms = round((time.perf_counter() - start) * 1000, 1)
        response.headers["x-request-id"] = request_id
        logging.getLogger("nabs.access").info(
            "request", extra={
                "request_id": request_id, "path": request.url.path,
                "method": request.method, "status_code": response.status_code,
                "duration_ms": duration_ms,
            })
        return response


def setup_metrics(app) -> bool:
    """Prometheus HTTP enstrümantasyonu (opsiyonel bağımlılık).
    İş metrikleri (business_metrics.py) burada DEĞİL, startup event'inde
    — migration'lar tamamlandıktan sonra — kaydedilir; aksi halde eski
    şemalı DB'de import anında sorgu patlar ve uygulama hiç açılamaz."""
    try:
        from prometheus_fastapi_instrumentator import Instrumentator
    except ImportError:
        return False
    Instrumentator().instrument(app).expose(app, endpoint="/metrics")
    return True
