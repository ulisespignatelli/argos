"""Defensas de la API: limite de consultas por cliente y cabeceras de seguridad."""
import time

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
}
DOCS_PATHS = ("/docs", "/redoc", "/openapi.json")   # Swagger necesita cargar sus propios recursos


class SecurityMiddleware(BaseHTTPMiddleware):
    """Token bucket por IP: `per_minute` consultas, con rafagas de hasta ese mismo numero."""

    def __init__(self, app, per_minute: int = 240):
        super().__init__(app)
        self.rate = per_minute / 60.0
        self.capacity = float(per_minute)
        self.buckets: dict[str, tuple[float, float]] = {}

    def _allow(self, key: str) -> tuple[bool, float]:
        now = time.monotonic()
        tokens, last = self.buckets.get(key, (self.capacity, now))
        tokens = min(self.capacity, tokens + (now - last) * self.rate)
        if len(self.buckets) > 10000:   # evita que la tabla crezca sin limite
            self.buckets.clear()
        if tokens < 1:
            self.buckets[key] = (tokens, now)
            return False, (1 - tokens) / self.rate
        self.buckets[key] = (tokens - 1, now)
        return True, 0.0

    async def dispatch(self, request: Request, call_next) -> Response:
        if request.url.path.startswith("/api/"):
            client = request.client.host if request.client else "desconocido"
            ok, wait = self._allow(client)
            if not ok:
                return JSONResponse({"detail": "demasiadas consultas"}, status_code=429,
                                    headers={"Retry-After": str(int(wait) + 1), **SECURITY_HEADERS})
        response = await call_next(request)
        if not request.url.path.startswith(DOCS_PATHS):
            for k, v in SECURITY_HEADERS.items():
                response.headers.setdefault(k, v)
        return response
