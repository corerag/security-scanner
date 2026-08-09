from datetime import datetime, timezone

from common.schemas import FileHashEntry, PersistenceReport, ProcessInfo, ScanReport


def test_scan_report_round_trips_through_json():
    report = ScanReport(
        scan_id="11111111-1111-1111-1111-111111111111",
        hostname="test-host",
        os_platform="Windows",
        os_version="10.0.26200",
        agent_version="1.0.0",
        scan_started_at=datetime.now(timezone.utc),
        scan_completed_at=datetime.now(timezone.utc),
        owner_email="owner@example.com",
        processes=[ProcessInfo(pid=1, name="init")],
        persistence=PersistenceReport(),
        file_hashes=[FileHashEntry(path="C:\\Windows\\System32\\cmd.exe", sha256="a" * 64, size_bytes=10)],
    )

    reloaded = ScanReport.model_validate_json(report.model_dump_json())

    assert reloaded.hostname == "test-host"
    assert reloaded.processes[0].pid == 1
    assert reloaded.file_hashes[0].sha256 == "a" * 64


def test_scan_report_rejects_invalid_owner_email():
    import pytest
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        ScanReport(
            scan_id="x",
            hostname="test-host",
            os_platform="Windows",
            os_version="10",
            agent_version="1.0.0",
            scan_started_at=datetime.now(timezone.utc),
            scan_completed_at=datetime.now(timezone.utc),
            owner_email="not-an-email",
        )
