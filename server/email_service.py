"""Sends the report-summary email to the admin and machine owner."""
from __future__ import annotations

from common.email_report import build_report_email, send_email
from common.schemas import ScanReport

from .config import ServerConfig


def send_report_email(report: ScanReport, cfg: ServerConfig) -> None:
    recipients = sorted({cfg.admin_email, report.owner_email})
    message = build_report_email(report, cfg.admin_email, cfg.smtp_from_address)
    send_email(
        message,
        smtp_host=cfg.smtp_host,
        smtp_port=cfg.smtp_port,
        use_tls=cfg.smtp_use_tls,
        username=cfg.smtp_username,
        password=cfg.smtp_password,
        from_address=cfg.smtp_from_address,
        recipients=recipients,
    )
