"""
Builds and sends the report-summary email. Shared by the FastAPI server
(server/email_service.py) and the agent's direct-email delivery mode
(agent/direct_email.py) so the two code paths can't drift apart.
"""
from __future__ import annotations

import smtplib
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from .schemas import ScanReport


def summarize_report(report: ScanReport) -> str:
    lines = [
        f"Security scan report for host: {report.hostname}",
        f"Scan ID:       {report.scan_id}",
        f"OS:            {report.os_platform} ({report.os_version})",
        f"Agent version: {report.agent_version}",
        f"Scan window:   {report.scan_started_at} -> {report.scan_completed_at}",
        "",
        "Summary:",
        f"  Processes observed:          {len(report.processes)}",
        f"  Network connections:         {len(report.network_connections)}",
        f"  Registry Run-key entries:    {len(report.persistence.registry_run_keys)}",
        f"  Scheduled tasks:              {len(report.persistence.scheduled_tasks)}",
        f"  Startup folder items:        {len(report.persistence.startup_items)}",
        f"  Files hashed:                {len(report.file_hashes)}",
    ]

    missing = [entry for entry in report.file_hashes if not entry.exists]
    if missing:
        lines.append("")
        lines.append(f"WARNING: {len(missing)} referenced file(s) could not be found on disk:")
        lines.extend(f"  - {entry.path}" for entry in missing[:20])
        if len(missing) > 20:
            lines.append(f"  ... and {len(missing) - 20} more")

    if report.notes:
        lines.append("")
        lines.append(f"Notes: {report.notes}")

    lines.append("")
    lines.append("Full details are attached as a JSON file.")
    return "\n".join(lines)


def build_report_email(report: ScanReport, admin_email: str, from_address: str) -> MIMEMultipart:
    recipients = sorted({admin_email, report.owner_email})

    message = MIMEMultipart()
    message["Subject"] = f"[Security Scan] {report.hostname} - {report.scan_completed_at:%Y-%m-%d %H:%M UTC}"
    message["From"] = from_address
    message["To"] = ", ".join(recipients)

    message.attach(MIMEText(summarize_report(report), "plain"))

    attachment = MIMEApplication(report.model_dump_json(indent=2).encode("utf-8"), _subtype="json")
    attachment.add_header("Content-Disposition", "attachment", filename=f"scan_{report.scan_id}.json")
    message.attach(attachment)

    return message


def send_email(
    message: MIMEMultipart,
    *,
    smtp_host: str,
    smtp_port: int,
    use_tls: bool,
    username: str,
    password: str,
    from_address: str,
    recipients: list[str],
) -> None:
    if not smtp_host:
        raise RuntimeError("SMTP host is not configured - cannot send email.")

    with smtplib.SMTP(smtp_host, smtp_port, timeout=30) as server:
        if use_tls:
            server.starttls()
        if username:
            server.login(username, password)
        server.sendmail(from_address, recipients, message.as_string())
