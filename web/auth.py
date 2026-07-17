"""Minimal session-based administrator authentication.

If ``DASHBOARD_ADMIN_PASSWORD`` is left blank in ``.env``, authentication is
disabled (suitable for a trusted local machine only). Setting a password
enables a login form guarding every dashboard page and API route.
"""
from __future__ import annotations

from urllib.parse import quote

from fastapi import Request
from fastapi.responses import RedirectResponse

from core.config import AppConfig

SESSION_KEY = "authenticated"


def auth_enabled(config: AppConfig) -> bool:
    return bool(config.admin_password)


def is_logged_in(request: Request) -> bool:
    config: AppConfig = request.app.state.config
    if not auth_enabled(config):
        return True
    return bool(request.session.get(SESSION_KEY))


def require_login(request: Request):
    """FastAPI dependency: redirects to /login for pages, or use for APIs.

    Raises a redirect via returning a Response is not how FastAPI deps work
    for APIs, so pages use :func:`require_login_page` and APIs check
    :func:`is_logged_in` directly and return 401.
    """
    return is_logged_in(request)


def require_login_page(request: Request):
    if not is_logged_in(request):
        # Preserve the full path *and* query string (e.g. drill-down filters
        # like ?status=processed) so signing back in returns to the same
        # filtered view instead of dropping the filter.
        target = request.url.path
        if request.url.query:
            target = f"{target}?{request.url.query}"
        return RedirectResponse(
            url=f"/login?next={quote(target, safe='')}", status_code=303
        )
    return None


def attempt_login(request: Request, username: str, password: str) -> bool:
    config: AppConfig = request.app.state.config
    if username == config.admin_username and password == config.admin_password:
        request.session[SESSION_KEY] = True
        return True
    return False


def logout(request: Request) -> None:
    request.session.pop(SESSION_KEY, None)
