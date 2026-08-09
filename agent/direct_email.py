"""
Direct-to-email delivery: builds and sends the report email straight from
the agent via SMTP, without needing the FastAPI report server reachable.

Used when DELIVERY_MODE=direct_email in .env - e.g. running the agent from
a USB drive against a machine that can't reach the report server.
"""
from __future__ import annotations

from common.email_report import build_report_email, send_email
from common.schemas import ScanReport

from . import config


def send_report_directly(report: ScanReport, cfg: config.AgentConfig) -> list[str]:
    """Builds and sends the report email directly. Returns the recipient list."""
    if not cfg.admin_email:
        raise RuntimeError("ADMIN_EMAIL is not configured - required for direct_email delivery mode.")

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
    return recipients
