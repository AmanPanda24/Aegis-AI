"""
Minimal in-memory rate limiter.

Not a substitute for a real gateway/WAF in production (state is per-process
and resets on restart), but the prototype previously had no throttling at
all, so a single client could hammer /api/export/alerts or the WebSocket
endpoint with no limit. This gives each IP a sliding-window cap and is enough
to stop naive abuse and accidental client bugs during local/VM use.
"""

import time
from collections import defaultdict, deque

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, max_requests: int = 120, window_seconds: int = 60):
        super().__init__(app)
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._hits = defaultdict(deque)

    async def dispatch(self, request: Request, call_next):
        client_ip = request.client.host if request.client else "unknown"
        now = time.time()
        window = self._hits[client_ip]

        while window and now - window[0] > self.window_seconds:
            window.popleft()

        if len(window) >= self.max_requests:
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded. Slow down."},
            )

        window.append(now)
        return await call_next(request)
