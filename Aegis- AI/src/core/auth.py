"""
API key authentication for Aegis-AI.

The prototype originally shipped with zero authentication - every REST
endpoint and the WebSocket feed were open to anyone who could reach the
port. This module adds a minimal but real API-key scheme:

- The key is read from the AEGIS_API_KEY environment variable (never
  committed to the repo, never stored in config.yaml).
- If no key is set in the environment, one is generated at startup and
  printed to the console ONCE, so local/dev use still works without any
  setup, but a fresh random key is required every restart unless the
  operator pins one via the environment.
- REST requests must send it as `X-API-Key: <key>`.
- The WebSocket endpoint requires it as a `?api_key=<key>` query param
  (browsers can't set custom headers on a WS handshake).
- Comparison uses `secrets.compare_digest` to avoid timing side-channels.
"""

import os
import secrets

from fastapi import Header, HTTPException, status, WebSocket

_ENV_VAR = "AEGIS_API_KEY"


def _load_or_generate_key() -> str:
    key = os.environ.get(_ENV_VAR)
    if key:
        return key

    generated = secrets.token_urlsafe(32)
    print("=" * 70)
    print("[AEGIS-AUTH] No AEGIS_API_KEY set in the environment.")
    print(f"[AEGIS-AUTH] Generated a temporary key for this run only:")
    print(f"[AEGIS-AUTH]   {generated}")
    print(f"[AEGIS-AUTH] Set AEGIS_API_KEY to pin a stable key across restarts.")
    print("=" * 70)
    return generated


API_KEY = _load_or_generate_key()


def require_api_key(x_api_key: str = Header(default=None, alias="X-API-Key")):
    """FastAPI dependency: raise 401 unless a valid X-API-Key header is present."""
    if not x_api_key or not secrets.compare_digest(x_api_key, API_KEY):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid API key. Send it as the X-API-Key header.",
        )
    return True


async def require_ws_api_key(websocket: WebSocket) -> bool:
    """WebSocket handshakes can't set custom headers from a browser, so the
    key is accepted as a query parameter instead: /ws?api_key=<key>.

    Query params are available on the ASGI scope before the handshake is
    accepted, so this checks - and rejects - BEFORE calling accept(). Doing
    the check after accept() (the first version of this fix) meant the
    client had already been told "connection open" before being kicked,
    which some WebSocket clients don't surface as a clean error."""
    supplied = websocket.query_params.get("api_key", "")
    if not supplied or not secrets.compare_digest(supplied, API_KEY):
        await websocket.close(code=4401)
        return False
    return True
