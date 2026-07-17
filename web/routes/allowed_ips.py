"""API + page routes for managing the allowed-IP allow list."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from core.allowed_ips_file import InvalidIPError, add_ip, list_ips, remove_ip

from .. import auth

router = APIRouter()
templates = Jinja2Templates(directory="web/templates")


def _require_api_auth(request: Request) -> None:
    if not auth.is_logged_in(request):
        raise HTTPException(status_code=401, detail="Authentication required")


def _path(request: Request) -> str:
    return request.app.state.config.allowed_ips_file


@router.get("/allowed-ips", response_class=HTMLResponse)
def allowed_ips_page(request: Request):
    redirect = auth.require_login_page(request)
    if redirect:
        return redirect
    return templates.TemplateResponse(request, "allowed_ips.html", {"active": "allowed-ips"})


@router.get("/api/allowed-ips")
def api_list_allowed_ips(request: Request):
    _require_api_auth(request)
    return {"ips": list_ips(_path(request))}


class AddIPBody(BaseModel):
    ip: str


@router.post("/api/allowed-ips")
def api_add_allowed_ip(request: Request, body: AddIPBody):
    _require_api_auth(request)
    try:
        added = add_ip(_path(request), body.ip)
    except InvalidIPError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not added:
        raise HTTPException(status_code=409, detail=f"{body.ip} is already on the allow list")
    return {"ips": list_ips(_path(request))}


@router.delete("/api/allowed-ips/{ip}")
def api_remove_allowed_ip(request: Request, ip: str):
    _require_api_auth(request)
    removed = remove_ip(_path(request), ip)
    if not removed:
        raise HTTPException(status_code=404, detail=f"{ip} was not found on the allow list")
    return {"ips": list_ips(_path(request))}
