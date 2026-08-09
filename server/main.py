"""
FastAPI report server.

Receives ScanReports from agents (authenticated with a shared API key),
stores them to disk, and emails a summary to the admin address and the
scanned machine's owner.

Run with:
    uvicorn server.main:app --host 0.0.0.0 --port 8000
"""
from __future__ import annotations

import logging

from fastapi import Depends, FastAPI, Header, HTTPException, status

from common.schemas import ReportAck, ScanReport

from . import config, email_service, storage

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("security-scanner-server")

app = FastAPI(
    title="Consent-Based Security Scanner - Report Server",
    version="1.0.0",
    description="Receives scan reports from authorized local agents and emails a summary.",
)

cfg = config.load_config()


def require_api_key(x_api_key: str = Header(default="", alias="X-API-Key")) -> None:
    if not x_api_key or x_api_key != cfg.api_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or missing API key.")


@app.get("/api/v1/health")
def health() -> dict:
    return {"status": "ok"}


@app.post(
    "/api/v1/reports",
    response_model=ReportAck,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_api_key)],
)
def receive_report(report: ScanReport) -> ReportAck:
    saved_path = storage.save_report(report, cfg.storage_dir)
    logger.info("Stored report %s for host %s at %s", report.scan_id, report.hostname, saved_path)

    email_sent = False
    try:
        email_service.send_report_email(report, cfg)
        email_sent = True
    except Exception:
        # The report is already safely stored on disk; don't fail the
        # request just because email delivery failed.
        logger.exception("Failed to send report email for scan %s", report.scan_id)

    return ReportAck(scan_id=report.scan_id, stored_at=saved_path, email_sent=email_sent)
