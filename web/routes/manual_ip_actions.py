"""API + page routes for manual (admin-triggered) IP block/unblock."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from core import database
from core.manual_actions import (
    IneligibleIPError,
    ProtectedIPError,
    manual_block_ip,
    manual_unblock_ip,
)
from core.rule_updater import RuleUpdateError

from .. import auth

router = APIRouter()
templates = Jinja2Templates(directory="web/templates")


def _require_api_auth(request: Request) -> None:
    if not auth.is_logged_in(request):
        raise HTTPException(status_code=401, detail="Authentication required")


@router.get("/manual-ip-actions", response_class=HTMLResponse)
def manual_ip_actions_page(request: Request):
    redirect = auth.require_login_page(request)
    if redirect:
        return redirect
    return templates.TemplateResponse(
        request, "manual_ip_actions.html", {"active": "manual-ip-actions"}
    )


class ManualBlockBody(BaseModel):
    ip: str
    reason: str = ""


@router.post("/api/manual-block")
def api_manual_block(request: Request, body: ManualBlockBody):
    _require_api_auth(request)
    config = request.app.state.config
    try:
        outcome = manual_block_ip(body.ip, body.reason, config)
    except IneligibleIPError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuleUpdateError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    if outcome.result == "duplicate":
        raise HTTPException(status_code=409, detail=outcome.detail)
    if outcome.result == "allowed":
        raise HTTPException(status_code=400, detail=outcome.detail)
    return {"success": True, "ip": outcome.ip, "detail": outcome.detail}


@router.get("/api/blocked-ips")
def api_list_blocked_ips(
    request: Request,
    search: str = "",
    status: str = "blocked",
    sort_by: str = "blocked_at",
    sort_dir: str = "desc",
    page: int = 1,
    page_size: int = 25,
):
    _require_api_auth(request)
    return database.query_blocked_ips(
        search=search, status=status, sort_by=sort_by, sort_dir=sort_dir,
        page=page, page_size=page_size,
    )


@router.delete("/api/blocked-ips/{ip}")
def api_manual_unblock(request: Request, ip: str):
    _require_api_auth(request)
    config = request.app.state.config
    try:
        outcome = manual_unblock_ip(ip, config)
    except ProtectedIPError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except RuleUpdateError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    if outcome.result == "not_blocked":
        raise HTTPException(status_code=404, detail=outcome.detail)
    return {"success": True, "ip": outcome.ip, "detail": outcome.detail}
