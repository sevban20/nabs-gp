"""Faz 2 Sprint 15-16: immutable audit middleware.

Tüm yazma isteklerini (POST/PUT/PATCH/DELETE) append-only audit_log
tablosuna kaydeder. Kullanıcı JWT'den çözülür; webhook gibi JWT'siz
uçlar 'ANONYMOUS' olarak yazılır. Audit yazımındaki bir hata isteği
asla engellemez (ama loglanır).
"""
import logging

from jose import jwt, JWTError
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from app.core.config import settings

logger = logging.getLogger("nabs.audit")
AUDITED_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


class AuditMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        if request.method in AUDITED_METHODS and request.url.path.startswith("/api/"):
            try:
                self._record(request, response.status_code)
            except Exception:  # noqa: BLE001 - audit asla isteği düşürmez
                logger.exception("Audit kaydı yazılamadı")
        return response

    @staticmethod
    def _record(request: Request, status_code: int) -> None:
        from app.core.database import SessionLocal
        from app.models.models import AuditLog

        username = "ANONYMOUS"
        auth = request.headers.get("authorization", "")
        if auth.lower().startswith("bearer "):
            try:
                claims = jwt.decode(auth[7:], settings.jwt_secret, algorithms=["HS256"])
                username = claims.get("sub", "ANONYMOUS")
            except JWTError:
                username = "INVALID_TOKEN"
        db = SessionLocal()
        try:
            db.add(AuditLog(
                username=username, method=request.method,
                path=str(request.url.path), status_code=status_code,
                source_ip=request.client.host if request.client else None,
            ))
            db.commit()
        finally:
            db.close()
