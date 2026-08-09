from datetime import datetime, timezone

import pytest

from agent import config, direct_email
from common.schemas import PersistenceReport, ScanReport


def _sample_report(owner_email: str = "owner@example.com") -> ScanReport:
    return ScanReport(
        scan_id="33333333-3333-3333-3333-333333333333",
        hostname="usb-host",
        os_platform="Windows",
        os_version="10",
        agent_version="1.0.0",
        scan_started_at=datetime.now(timezone.utc),
        scan_completed_at=datetime.now(timezone.utc),
        owner_email=owner_email,
        persistence=PersistenceReport(),
    )


def test_send_report_directly_emails_both_admin_and_owner(monkeypatch):
    sent = {}

    def fake_send_email(message, **kwargs):
        sent["message"] = message
        sent["kwargs"] = kwargs

    monkeypatch.setattr(direct_email, "send_email", fake_send_email)

    cfg = config.AgentConfig(
        delivery_mode="direct_email",
        owner_email="owner@example.com",
        admin_email="admin@example.com",
        smtp_host="smtp.example.com",
        smtp_from_address="scanner@example.com",
    )

    recipients = direct_email.send_report_directly(_sample_report(), cfg)

    assert recipients == ["admin@example.com", "owner@example.com"]
    assert sent["kwargs"]["smtp_host"] == "smtp.example.com"
    assert sent["kwargs"]["from_address"] == "scanner@example.com"
    assert sent["kwargs"]["recipients"] == ["admin@example.com", "owner@example.com"]
    assert "usb-host" in sent["message"]["Subject"]


def test_send_report_directly_requires_admin_email():
    cfg = config.AgentConfig(
        delivery_mode="direct_email",
        owner_email="owner@example.com",
        admin_email=None,
        smtp_host="smtp.example.com",
    )

    with pytest.raises(RuntimeError, match="ADMIN_EMAIL"):
        direct_email.send_report_directly(_sample_report(), cfg)
