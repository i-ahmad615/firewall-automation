"""FastAPI application factory for the integrated SOC dashboard."""
from __future__ import annotations

import secrets
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from core.config import AppConfig

from .routes import allowed_ips, api, export, pages


def _load_or_create_session_secret(database_path: str) -> str:
    """Return a session signing secret that survives process restarts.

    Stored next to the SQLite database so admins stay logged in across
    ``python main.py`` restarts instead of every restart silently logging
    everyone out (and, worse, dropping any URL query string -- e.g. a
    dashboard drill-down filter -- through the login redirect).
    """
    secret_path = Path(database_path).parent / ".session_secret"
    secret_path.parent.mkdir(parents=True, exist_ok=True)
    if secret_path.exists():
        return secret_path.read_text(encoding="utf-8").strip()
    secret = secrets.token_hex(32)
    secret_path.write_text(secret, encoding="utf-8")
    return secret


class _NoCacheStaticFiles(StaticFiles):
    """Serve /static/* with Cache-Control: no-cache.

    Browsers still cache the response but must revalidate with the server
    (via ETag/Last-Modified) before reusing it, so CSS/JS edits show up on a
    normal refresh instead of silently serving a stale cached copy.
    """

    async def get_response(self, path: str, scope):
        response = await super().get_response(path, scope)
        response.headers["Cache-Control"] = "no-cache"
        return response


def create_app(config: AppConfig) -> FastAPI:
    app = FastAPI(title="Security Alert Automation", docs_url=None, redoc_url=None)
    app.state.config = config

    session_secret = _load_or_create_session_secret(config.database_path)
    app.add_middleware(SessionMiddleware, secret_key=session_secret)

    app.mount("/static", _NoCacheStaticFiles(directory="web/static"), name="static")

    app.include_router(pages.router)
    app.include_router(api.router)
    app.include_router(export.router)
    app.include_router(allowed_ips.router)

    return app
