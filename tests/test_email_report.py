from datetime import datetime, timezone

from common.email_report import summarize_report
from common.schemas import FileHashEntry, PersistenceReport, ScanReport


def _report(file_hashes, ai_summary=None):
    return ScanReport(
        scan_id="44444444-4444-4444-4444-444444444444",
        hostname="test-host",
        os_platform="Windows",
        os_version="10",
        agent_version="1.0.0",
        scan_started_at=datetime.now(timezone.utc),
        scan_completed_at=datetime.now(timezone.utc),
        owner_email="owner@example.com",
        persistence=PersistenceReport(),
        file_hashes=file_hashes,
        ai_summary=ai_summary,
    )


def test_summary_omits_virustotal_lines_when_not_checked():
    report = _report([FileHashEntry(path="C:\\a.exe", sha256="a" * 64, size_bytes=1)])

    summary = summarize_report(report)

    assert "VirusTotal" not in summary


def test_summary_reports_virustotal_counts_when_checked():
    report = _report(
        [
            FileHashEntry(
                path="C:\\clean.exe",
                sha256="a" * 64,
                size_bytes=1,
                vt_malicious_count=0,
                vt_total_engines=70,
            ),
            FileHashEntry(
                path="C:\\bad.exe",
                sha256="b" * 64,
                size_bytes=1,
                vt_malicious_count=12,
                vt_total_engines=70,
            ),
        ]
    )

    summary = summarize_report(report)

    assert "VirusTotal hashes checked:    2" in summary
    assert "VirusTotal-flagged malicious: 1" in summary
    assert "WARNING: 1 file(s) flagged as malicious by VirusTotal" in summary
    assert "C:\\bad.exe - 12/70 engines" in summary
    assert "C:\\clean.exe" not in summary.split("WARNING: 1 file(s)")[1]


def test_summary_omits_ai_section_when_no_summary():
    report = _report([FileHashEntry(path="C:\\a.exe", sha256="a" * 64, size_bytes=1)])

    summary = summarize_report(report)

    assert "AI TRIAGE SUMMARY" not in summary


def test_summary_places_ai_summary_near_the_top():
    report = _report(
        [FileHashEntry(path="C:\\a.exe", sha256="a" * 64, size_bytes=1)],
        ai_summary="Nothing alarming here; consider reviewing a.exe just in case.",
    )

    summary = summarize_report(report)

    assert "AI TRIAGE SUMMARY" in summary
    assert "Nothing alarming here; consider reviewing a.exe just in case." in summary
    # The AI summary must appear before the technical "Summary:" stats block,
    # i.e. it's the first thing a human reads.
    assert summary.index("AI TRIAGE SUMMARY") < summary.index("Summary:")
