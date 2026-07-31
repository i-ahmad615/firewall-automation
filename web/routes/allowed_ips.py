"""Protected Endpoints page and backward-compatible /allowed-ips API routes."""
from __future__ import annotations

import csv
import io
import json
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, Response
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from core import database
from core.endpoint_registry import infer_value_type, normalize_value
from .. import auth

router = APIRouter()
templates = Jinja2Templates(directory="web/templates")
CATEGORIES = {"CENTURY_OWNED", "EXTERNAL_ALLOWLIST"}
TYPES = {"IP", "CIDR", "HOSTNAME"}


def _require(request: Request) -> None:
    if not auth.is_logged_in(request):
        raise HTTPException(status_code=401, detail="Authentication required")


def _actor(request: Request) -> str:
    return getattr(request.app.state.config, "admin_username", "") or "dashboard-admin"


def _category(value: str) -> str:
    category = (value or "").strip().upper()
    if not category:
        raise HTTPException(status_code=400, detail="Category is required.")
    if category not in CATEGORIES:
        raise HTTPException(status_code=400, detail="Invalid category.")
    return category


def _validated(value: str, value_type: str = "") -> tuple[str, str]:
    try:
        return normalize_value(value, value_type or None)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def _conflict(normalized: str, category: str, ignore_id: int = 0) -> None:
    existing = database.get_protected_endpoint_by_normalized(normalized)
    if existing and int(existing["id"]) != ignore_id:
        detail = ("This endpoint already exists." if existing["category"] == category
                  else "This endpoint already exists under another category.")
        raise HTTPException(status_code=409, detail=detail)


@router.get("/allowed-ips", response_class=HTMLResponse)
def allowed_ips_page(request: Request):
    redirect = auth.require_login_page(request)
    if redirect:
        return redirect
    return templates.TemplateResponse(request, "allowed_ips.html", {"active": "allowed-ips"})


@router.get("/api/allowed-ips")
def api_list_allowed_ips(request: Request, search: str = "", category: str = "", value_type: str = ""):
    _require(request)
    if category and category.upper() not in CATEGORIES:
        raise HTTPException(status_code=400, detail="Invalid category.")
    if value_type and value_type.upper() not in TYPES:
        raise HTTPException(status_code=400, detail="Invalid endpoint type.")
    return {"endpoints": database.list_protected_endpoints(
        search=search.strip(), category=category.upper(), value_type=value_type.upper()
    )}


class EndpointBody(BaseModel):
    value: str
    value_type: str = ""
    category: str
    description: str = ""
    is_active: bool = True


@router.post("/api/allowed-ips")
def api_add_allowed_ip(request: Request, body: EndpointBody):
    _require(request)
    category = _category(body.category)
    normalized, kind = _validated(body.value, body.value_type)
    _conflict(normalized, category)
    entry_id = database.add_protected_endpoint(
        body.value, normalized, kind, category, body.description,
        active=body.is_active, actor=_actor(request),
    )
    if entry_id is None:
        raise HTTPException(status_code=409, detail="This endpoint already exists.")
    return {"endpoint": database.get_protected_endpoint(entry_id)}


@router.put("/api/allowed-ips/{entry_id}")
def api_edit_allowed_ip(request: Request, entry_id: int, body: EndpointBody):
    _require(request)
    if not database.get_protected_endpoint(entry_id):
        raise HTTPException(status_code=404, detail="Protected endpoint was not found.")
    category = _category(body.category)
    normalized, kind = _validated(body.value, body.value_type)
    _conflict(normalized, category, entry_id)
    if not database.update_protected_endpoint(
        entry_id, value=body.value, normalized_value=normalized, value_type=kind,
        category=category, description=body.description, active=body.is_active,
        actor=_actor(request),
    ):
        raise HTTPException(status_code=409, detail="This endpoint already exists.")
    return {"endpoint": database.get_protected_endpoint(entry_id)}


class ActiveBody(BaseModel):
    is_active: bool


@router.patch("/api/allowed-ips/{entry_id}")
def api_set_endpoint_active(request: Request, entry_id: int, body: ActiveBody):
    _require(request)
    if not database.set_protected_endpoint_active(entry_id, body.is_active, actor=_actor(request)):
        raise HTTPException(status_code=404, detail="Protected endpoint was not found.")
    return {"endpoint": database.get_protected_endpoint(entry_id)}


@router.delete("/api/allowed-ips/{entry_id}")
def api_remove_allowed_ip(request: Request, entry_id: int):
    _require(request)
    if not database.delete_protected_endpoint(entry_id, actor=_actor(request)):
        raise HTTPException(status_code=404, detail="Protected endpoint was not found.")
    return {"deleted": entry_id}


@router.get("/api/protected-endpoints/export")
def api_export_endpoints(request: Request, format: str = "csv"):
    _require(request)
    rows = database.list_protected_endpoints()
    fields = ["value", "normalized_value", "value_type", "category", "description",
              "is_active", "created_at", "updated_at"]
    if format.lower() == "json":
        content = json.dumps([{key: row.get(key) for key in fields} for row in rows], indent=2)
        media, suffix = "application/json", "json"
    elif format.lower() == "csv":
        stream = io.StringIO()
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows({key: row.get(key) for key in fields} for row in rows)
        content, media, suffix = stream.getvalue(), "text/csv", "csv"
    else:
        raise HTTPException(status_code=400, detail="Export format must be csv or json.")
    database.record_endpoint_audit("EXPORTED", endpoint_value=f"{len(rows)} endpoints",
                                   new_data={"format": suffix, "count": len(rows)}, actor=_actor(request))
    return Response(content, media_type=media,
                    headers={"Content-Disposition": f'attachment; filename="protected_endpoints.{suffix}"'})


class ImportBody(BaseModel):
    format: str
    content: str


def _import_rows(body: ImportBody) -> list[dict[str, Any]]:
    try:
        if body.format.lower() == "json":
            parsed = json.loads(body.content)
            if not isinstance(parsed, list):
                raise ValueError("JSON must contain an array of endpoint objects.")
            return [item for item in parsed if isinstance(item, dict)]
        if body.format.lower() == "csv":
            return list(csv.DictReader(io.StringIO(body.content)))
    except (ValueError, csv.Error, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail=f"Invalid import file: {exc}") from exc
    raise HTTPException(status_code=400, detail="Import format must be csv or json.")


@router.post("/api/protected-endpoints/import")
def api_import_endpoints(request: Request, body: ImportBody):
    _require(request)
    summary: dict[str, Any] = {"imported": 0, "duplicates": 0, "conflicts": 0,
                               "invalid": 0, "errors": []}
    for number, raw in enumerate(_import_rows(body), start=2):
        row = {str(k).strip().lower().replace(" ", "_"): v for k, v in raw.items()}
        value = str(row.get("value") or "").strip()
        category = str(row.get("category") or "").strip().upper()
        try:
            if category not in CATEGORIES:
                raise ValueError("Category is required or invalid.")
            kind = infer_value_type(value)
            normalized, kind = normalize_value(value, kind)
            existing = database.get_protected_endpoint_by_normalized(normalized)
            if existing:
                bucket = "duplicates" if existing["category"] == category else "conflicts"
                summary[bucket] += 1
                summary["errors"].append({"row": number, "value": value, "error":
                    "This endpoint already exists." if bucket == "duplicates"
                    else "This endpoint already exists under another category."})
                continue
            active_raw = str(row.get("is_active", row.get("active_status", "true"))).strip().lower()
            active = active_raw not in {"0", "false", "no", "disabled", "inactive"}
            database.add_protected_endpoint(
                value, normalized, kind, category, str(row.get("description") or ""),
                active=active, actor=_actor(request), audit_action="IMPORTED",
            )
            summary["imported"] += 1
        except ValueError as exc:
            summary["invalid"] += 1
            summary["errors"].append({"row": number, "value": value, "error": str(exc)})
    database.record_endpoint_audit("IMPORTED", endpoint_value="Manual import",
                                   new_data=summary, actor=_actor(request))
    return summary
