"""Server-rendered dashboard pages."""
from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from .. import auth
from ..services import settings_service

router = APIRouter()
templates = Jinja2Templates(directory="web/templates")


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request, error: str = ""):
    config = request.app.state.config
    if not auth.auth_enabled(config):
        return RedirectResponse(url="/")
    return templates.TemplateResponse(request, "login.html", {"error": error})


@router.post("/login")
async def login_submit(request: Request):
    form = await request.form()
    username = str(form.get("username", ""))
    password = str(form.get("password", ""))
    next_url = str(form.get("next") or "/")
    if auth.attempt_login(request, username, password):
        return RedirectResponse(url=next_url, status_code=303)
    return RedirectResponse(url="/login?error=1", status_code=303)


@router.get("/logout")
def logout(request: Request):
    auth.logout(request)
    return RedirectResponse(url="/login")


def _guarded(request: Request):
    return auth.require_login_page(request)


@router.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    redirect = _guarded(request)
    if redirect:
        return redirect
    return templates.TemplateResponse(request, "dashboard.html", {"active": "dashboard"})


@router.get("/alerts", response_class=HTMLResponse)
def alerts_page(request: Request):
    redirect = _guarded(request)
    if redirect:
        return redirect
    return templates.TemplateResponse(request, "alerts.html", {"active": "alerts"})


@router.get("/firewall", response_class=HTMLResponse)
def firewall_page(request: Request):
    redirect = _guarded(request)
    if redirect:
        return redirect
    return templates.TemplateResponse(request, "firewall.html", {"active": "firewall"})


@router.get("/firewall-console")
def open_firewall_console(request: Request):
    """Open the configured Sophos console without exposing API credentials."""
    redirect = _guarded(request)
    if redirect:
        return redirect
    config = request.app.state.config
    host = config.firewall_host.strip()
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return RedirectResponse(
        url=f"https://{host}:{config.firewall_port}/",
        status_code=307,
    )


@router.get("/failed-ip-queue", response_class=HTMLResponse)
def failed_ip_queue_page(request: Request):
    redirect = _guarded(request)
    if redirect:
        return redirect
    return templates.TemplateResponse(
        request, "failed_ip_queue.html", {"active": "failed-ip-queue"}
    )


@router.get("/logs", response_class=HTMLResponse)
def logs_page(request: Request):
    redirect = _guarded(request)
    if redirect:
        return redirect
    return templates.TemplateResponse(request, "logs.html", {"active": "logs"})


@router.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, saved: str = "", error: str = ""):
    redirect = _guarded(request)
    if redirect:
        return redirect
    return templates.TemplateResponse(
        request,
        "settings.html",
        {
            "active": "settings",
            "sections": settings_service.load_settings(),
            "saved": saved,
            "error": error,
        },
    )


@router.post("/settings")
async def settings_submit(request: Request):
    redirect = _guarded(request)
    if redirect:
        return redirect
    form = await request.form()
    errors = settings_service.save_settings({k: str(v) for k, v in form.items()})
    if errors:
        return RedirectResponse(
            url=f"/settings?error={'; '.join(errors)}", status_code=303
        )
    return RedirectResponse(url="/settings?saved=1", status_code=303)
