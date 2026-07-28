"""JSON API: stats, alerts, firewall actions, logs, and the live SSE feed."""
from __future__ import annotations

import asyncio
import json
import queue as queue_module
from datetime import datetime, timedelta

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from core import (
    database, email_connectivity_monitor, email_status, event_bus,
    firewall_monitor, firewall_status,
)
from core.manual_actions import retry_now
from .. import auth

router = APIRouter(prefix="/api")


class DeleteSelectedBody(BaseModel):
    ids: list[int]


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


@router.get("/imap-status")
def get_imap_status(request: Request):
    _require_api_auth(request)
    return email_status.get_status("imap")


@router.post("/imap-status/check")
def check_imap_status(request: Request):
    _require_api_auth(request)
    email_connectivity_monitor.check_imap_once(request.app.state.config)
    return email_status.get_status("imap")


@router.get("/smtp-status")
def get_smtp_status(request: Request):
    _require_api_auth(request)
    return email_status.get_status("smtp")


@router.post("/smtp-status/check")
def check_smtp_status(request: Request):
    _require_api_auth(request)
    email_connectivity_monitor.check_smtp_once(request.app.state.config)
    return email_status.get_status("smtp")


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


def _compute_next_retry(last_attempt_at: str, interval_seconds: int) -> str:
    try:
        dt = datetime.fromisoformat(last_attempt_at)
    except (TypeError, ValueError):
        return ""
    return (dt + timedelta(seconds=interval_seconds)).isoformat()


@router.get("/pending-blocks")
def pending_blocks(
    request: Request,
    search: str = "",
    sort_by: str = "last_attempt_at",
    sort_dir: str = "desc",
    page: int = 1,
    page_size: int = 25,
):
    _require_api_auth(request)
    result = database.query_pending_blocks(
        search=search, sort_by=sort_by, sort_dir=sort_dir,
        page=page, page_size=page_size,
    )
    interval = request.app.state.config.poll_interval
    for row in result["rows"]:
        row["next_retry_at"] = (
            _compute_next_retry(row["last_attempt_at"], interval)
            if row.get("active", True) else ""
        )
    return result


@router.delete("/pending-blocks/{ip}")
def remove_pending_block(ip: str, request: Request):
    _require_api_auth(request)
    removed = database.cancel_pending_block(ip)
    if not removed:
        raise HTTPException(status_code=404, detail="IP not found in retry queue")
    return {"removed": True, "ip": ip}


@router.post("/pending-blocks/{ip}/stop")
def stop_pending_block(ip: str, request: Request):
    _require_api_auth(request)
    stopped = database.stop_pending_block(ip)
    if not stopped:
        raise HTTPException(status_code=404, detail="Active retry not found")
    return {"stopped": True, "ip": ip}


@router.post("/pending-blocks/{ip}/pause")
def pause_pending_block(ip: str, request: Request):
    _require_api_auth(request)
    paused = database.stop_pending_block(ip)
    if not paused:
        raise HTTPException(status_code=404, detail="Active retry not found")
    return {"paused": True, "ip": ip}


@router.post("/pending-blocks/{ip}/resume")
def resume_pending_block(ip: str, request: Request):
    _require_api_auth(request)
    resumed = database.resume_pending_block(ip)
    if not resumed:
        raise HTTPException(status_code=404, detail="Paused retry not found")
    return {"resumed": True, "ip": ip}


@router.post("/pending-blocks/{ip}/retry-now")
def retry_pending_block_now(ip: str, request: Request):
    """Immediately retry a queued IP without waiting for the next automatic
    polling cycle. A failed retry is a normal outcome (200, result=
    "still_failing"), not an error -- only "IP not queued" returns non-200."""
    _require_api_auth(request)
    config = request.app.state.config
    try:
        outcome = retry_now(ip, config)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"result": outcome.result, "ip": outcome.ip, "detail": outcome.detail}


@router.get("/logs")
def logs(
    request: Request,
    search: str = "",
    severity: str = "",
    category: str = "",
    date_from: str = "",
    date_to: str = "",
    sort_dir: str = "desc",
    page: int = 1,
    page_size: int = 50,
):
    _require_api_auth(request)
    result = database.query_logs(
        search=search, severity=severity, module=category,
        date_from=date_from, date_to=date_to, sort_dir=sort_dir,
        page=page, page_size=page_size,
    )
    result["categories"] = database.distinct_modules()
    return result


@router.delete("/alerts")
def clear_alerts(request: Request):
    _require_api_auth(request)
    deleted = database.clear_table("alerts")
    return {"deleted": deleted}


@router.post("/alerts/delete-selected")
def delete_selected_alerts(body: DeleteSelectedBody, request: Request):
    _require_api_auth(request)
    if not body.ids:
        raise HTTPException(status_code=400, detail="Select at least one alert")
    if len(body.ids) > 500:
        raise HTTPException(status_code=400, detail="A maximum of 500 alerts can be deleted at once")
    deleted = database.delete_rows_by_ids("alerts", body.ids)
    return {"deleted": deleted}


@router.delete("/firewall-actions")
def clear_firewall_actions(request: Request):
    _require_api_auth(request)
    deleted = database.clear_table("firewall_actions")
    return {"deleted": deleted}


@router.post("/firewall-actions/delete-selected")
def delete_selected_firewall_actions(body: DeleteSelectedBody, request: Request):
    _require_api_auth(request)
    if not body.ids:
        raise HTTPException(status_code=400, detail="Select at least one firewall action")
    if len(body.ids) > 500:
        raise HTTPException(
            status_code=400,
            detail="A maximum of 500 firewall actions can be deleted at once",
        )
    deleted = database.delete_rows_by_ids("firewall_actions", body.ids)
    return {"deleted": deleted}


@router.delete("/logs")
def clear_logs(request: Request):
    _require_api_auth(request)
    deleted = database.clear_table("logs")
    return {"deleted": deleted}


def _server_shutting_down(request: Request) -> bool:
    """True once uvicorn has caught Ctrl+C and is trying to shut down.

    Lets long-lived requests like the SSE feed below notice a server-
    initiated shutdown, not just a client disconnect, so they can exit on
    their own within a couple seconds instead of needing to be forcibly
    cancelled (which is slow -- see _get_with_timeout -- and logs a scary
    but harmless "Cancel N running task(s)" error).
    """
    server = getattr(request.app.state, "server", None)
    return bool(server is not None and server.should_exit)


@router.get("/events")
async def events(request: Request):
    _require_api_auth(request)

    def _get_with_timeout(q: "queue_module.Queue"):
        try:
            # Short so the loop below re-checks for a server shutdown (or a
            # client disconnect) every couple seconds rather than being
            # stuck inside this blocking call -- on a worker thread, which
            # can't be interrupted once started -- for up to 15s at a time.
            return q.get(timeout=2)
        except queue_module.Empty:
            return None

    async def event_source():
        queue = event_bus.subscribe()
        try:
            yield "retry: 3000\n\n"
            while True:
                if await request.is_disconnected() or _server_shutting_down(request):
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
