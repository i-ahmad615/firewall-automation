"""Export endpoints for alerts / firewall actions / logs (CSV + Excel)."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import Response

from .. import auth
from ..services import export_service

router = APIRouter(prefix="/api/export")

_VALID_TABLES = {"alerts", "firewall_actions", "logs"}
_VALID_FORMATS = {"csv", "xlsx"}


@router.get("/{table}.{fmt}")
def export_table(request: Request, table: str, fmt: str):
    if not auth.is_logged_in(request):
        raise HTTPException(status_code=401, detail="Authentication required")
    if table not in _VALID_TABLES:
        raise HTTPException(status_code=404, detail="Unknown export table")
    if fmt not in _VALID_FORMATS:
        raise HTTPException(status_code=400, detail="Unsupported export format")

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    filename = f"{table}-{stamp}.{fmt}"

    if fmt == "csv":
        content = export_service.to_csv(table)  # type: ignore[arg-type]
        media_type = "text/csv"
    else:
        content = export_service.to_xlsx(table)  # type: ignore[arg-type]
        media_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
