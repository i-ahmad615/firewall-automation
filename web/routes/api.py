"""JSON API: stats, alerts, firewall actions, logs, and the live SSE feed."""
from __future__ import annotations

import asyncio
import json
import queue as queue_module

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import StreamingResponse

from core import database, event_bus, firewall_monitor, firewall_status
from .. import auth

router = APIRouter(prefix="/api")


def _require_api_auth(request: Request) -> None:
    if not auth.is_logged_in(request):
        raise HTTPException(status_code=401, detail="Authentication required")


@router.get("/stats")
def stats(request: Request):
    _require_api_auth(request)
    return database.get_stats()


@router.get("/firewall-status")
def get_firewall_status(request: Request):
    _require_api_auth(request)
    return firewall_status.get_status()


@router.post("/firewall-status/check")
def check_firewall_status(request: Request):
    _require_api_auth(request)
    firewall_monitor.check_once(request.app.state.config)
    return firewall_status.get_status()


@router.get("/stats/timeseries")
def stats_timeseries(request: Request, days: int = 14):
    _require_api_auth(request)
    return {
        "series": database.alerts_timeseries(days=days),
        "breakdown": database.action_breakdown(),
    }


@router.get("/alerts")
def alerts(
    request: Request,
    search: str = "",
    classification: str = "",
    status: str = "",
    action_taken: str = "",
    notification_sent: str = "",
    sort_by: str = "received_at",
    sort_dir: str = "desc",
    page: int = 1,
    page_size: int = 25,
):
    _require_api_auth(request)
    notif_filter = None
    if notification_sent in ("1", "true", "True"):
        notif_filter = True
    elif notification_sent in ("0", "false", "False"):
        notif_filter = False
    return database.query_alerts(
        search=search, classification=classification, status=status,
        action_taken=action_taken, notification_sent=notif_filter,
        sort_by=sort_by, sort_dir=sort_dir,
        page=page, page_size=page_size,
    )


@router.get("/firewall-actions")
def firewall_actions(
    request: Request,
    search: str = "",
    result: str = "",
    status: str = "",
    sort_by: str = "occurred_at",
    sort_dir: str = "desc",
    page: int = 1,
    page_size: int = 25,
):
    _require_api_auth(request)
    return database.query_firewall_actions(
        search=search, result=result, status=status,
        sort_by=sort_by, sort_dir=sort_dir, page=page, page_size=page_size,
    )


@router.get("/logs")
def logs(
    request: Request,
    search: str = "",
    severity: str = "",
    module: str = "",
    date_from: str = "",
    date_to: str = "",
    sort_dir: str = "desc",
    page: int = 1,
    page_size: int = 50,
):
    _require_api_auth(request)
    result = database.query_logs(
        search=search, severity=severity, module=module,
        date_from=date_from, date_to=date_to, sort_dir=sort_dir,
        page=page, page_size=page_size,
    )
    result["modules"] = database.distinct_modules()
    return result


@router.delete("/alerts")
def clear_alerts(request: Request):
    _require_api_auth(request)
    deleted = database.clear_table("alerts")
    return {"deleted": deleted}


@router.delete("/firewall-actions")
def clear_firewall_actions(request: Request):
    _require_api_auth(request)
    deleted = database.clear_table("firewall_actions")
    return {"deleted": deleted}


@router.delete("/logs")
def clear_logs(request: Request):
    _require_api_auth(request)
    deleted = database.clear_table("logs")
    return {"deleted": deleted}


@router.get("/events")
async def events(request: Request):
    _require_api_auth(request)

    def _get_with_timeout(q: "queue_module.Queue"):
        try:
            return q.get(timeout=15)
        except queue_module.Empty:
            return None

    async def event_source():
        queue = event_bus.subscribe()
        try:
            yield "retry: 3000\n\n"
            while True:
                if await request.is_disconnected():
                    break
                item = await asyncio.get_event_loop().run_in_executor(
                    None, _get_with_timeout, queue
                )
                if item is None:
                    yield ": keep-alive\n\n"
                    continue
                yield f"data: {json.dumps(item)}\n\n"
        finally:
            event_bus.unsubscribe(queue)

    return StreamingResponse(event_source(), media_type="text/event-stream")
