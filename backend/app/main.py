"""NABS-GP API entrypoint.

Every router declares its access model explicitly (Spec Section 7):
- /api/v1/auth/token         : public (credential exchange)
- /api/v1/webhook/sftpgo     : HMAC-verified (no user JWT)
- /metrics, /health          : infra endpoints
- everything else            : JWT + role dependency per endpoint

Bölüm 11: JSON structured logging + request-ID korelasyonu + Prometheus.
Faz 2:    immutable audit middleware (yazma istekleri).
"""
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.endpoints import (
    advisories, ai, apikeys, assets, auth, compliance, credentials, dashboard,
    discovery, jobs, remediations, reports, settings as settings_ep, system,
    users, webhooks,
)
from app.core.audit import AuditMiddleware
from app.core.database import Base, engine
from app.core.observability import RequestIdMiddleware, configure_json_logging, setup_metrics

configure_json_logging()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Başlangıç: önce mevcut tablolara eksik kolonları ekle (eski DB + yeni
    # kod kombinasyonunda 500'leri önler), sonra yeni tabloları oluştur.
    from app.core.migrations import run_startup_migrations
    run_startup_migrations(engine)
    Base.metadata.create_all(bind=engine)
    # İş metrikleri ancak şema hazır olduktan sonra kaydedilir.
    if METRICS_ENABLED:
        from app.core.business_metrics import register_business_metrics
        register_business_metrics()
    yield


app = FastAPI(
    title="NABS-GP",
    description="Network Asset, Backup and Security Governance Platform",
    version="1.1.0",
    # Docs'u /api/ altına al ki nginx proxy'si (location /api/) üzerinden
    # dashboard'la aynı origin'den erişilebilsin.
    docs_url="/api/docs",
    openapi_url="/api/openapi.json",
    redoc_url="/api/redoc",
    lifespan=lifespan,
)

app.add_middleware(AuditMiddleware)
app.add_middleware(RequestIdMiddleware)

# CORS origin'leri yapılandırılabilir (virgülle ayrık). Dağıtımda dashboard'un
# gerçek origin'ini CORS_ORIGINS'e verin; varsayılan lokal geliştirme.
import os  # noqa: E402
_cors_origins = [o.strip() for o in
                 os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

METRICS_ENABLED = setup_metrics(app)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request, exc):
    """500'leri sessizce yutma: request-ID ile logla, teşhis edilebilir
    bir gövde döndür (fail closed ama görünür)."""
    import logging

    from fastapi.responses import JSONResponse

    request_id = getattr(request.state, "request_id", "-")
    logging.getLogger("nabs.error").exception(
        "Unhandled error", extra={"request_id": request_id,
                                  "path": str(request.url.path)})
    return JSONResponse(status_code=500, content={
        "detail": f"Sunucu hatası: {type(exc).__name__}. "
                  f"Loglarda request_id={request_id} arayın.",
        "request_id": request_id,
    })


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "nabs-gp", "version": "1.1.0",
            "metrics": METRICS_ENABLED}


API_PREFIX = "/api/v1"
app.include_router(auth.router, prefix=API_PREFIX, tags=["auth"])
app.include_router(assets.router, prefix=API_PREFIX, tags=["assets"])
app.include_router(credentials.router, prefix=API_PREFIX, tags=["credentials"])
app.include_router(advisories.router, prefix=API_PREFIX, tags=["advisories"])
app.include_router(remediations.router, prefix=API_PREFIX, tags=["remediations"])
app.include_router(webhooks.router, prefix=API_PREFIX, tags=["webhooks"])
app.include_router(discovery.router, prefix=API_PREFIX, tags=["discovery"])
app.include_router(reports.router, prefix=API_PREFIX, tags=["reports"])
app.include_router(ai.router, prefix=API_PREFIX, tags=["ai"])
app.include_router(dashboard.router, prefix=API_PREFIX, tags=["dashboard"])
app.include_router(apikeys.router, prefix=API_PREFIX, tags=["apikeys"])
app.include_router(compliance.router, prefix=API_PREFIX, tags=["compliance"])
app.include_router(jobs.router, prefix=API_PREFIX, tags=["jobs"])
app.include_router(settings_ep.router, prefix=API_PREFIX, tags=["settings"])
app.include_router(users.router, prefix=API_PREFIX, tags=["users"])
app.include_router(system.router, prefix=API_PREFIX, tags=["system"])
