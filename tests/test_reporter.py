from agent import config
from agent.reporter import build_report


def test_build_report_produces_valid_report():
    cfg = config.load_config()
    report = build_report(cfg)

    assert report.hostname
    assert report.owner_email == cfg.owner_email
    assert report.scan_completed_at >= report.scan_started_at
    assert isinstance(report.processes, list)
    assert isinstance(report.file_hashes, list)

    # No VIRUSTOTAL_API_KEY is set in the test environment, so the lookup
    # step must be skipped (no network calls, fields left unset).
    assert all(entry.vt_malicious_count is None for entry in report.file_hashes)

    # Likewise no ANTHROPIC_API_KEY is set, so AI triage must be skipped.
    assert report.ai_summary is None


def test_build_report_enriches_file_hashes_with_virustotal(monkeypatch):
    from common.schemas import FileHashEntry

    cfg = config.load_config()
    cfg.virustotal_api_key = "test-vt-key"

    monkeypatch.setattr(
        "agent.reporter.enrich_with_virustotal",
        lambda file_hashes, api_key: [
            entry.model_copy(update={"vt_malicious_count": 2, "vt_total_engines": 70})
            for entry in file_hashes
        ]
        if api_key
        else file_hashes,
    )
    monkeypatch.setattr(
        "agent.reporter.hash_paths",
        lambda paths: [FileHashEntry(path="C:\\fake.exe", sha256="a" * 64, size_bytes=1)],
    )

    report = build_report(cfg)

    assert len(report.file_hashes) == 1
    assert report.file_hashes[0].vt_malicious_count == 2
    assert report.file_hashes[0].vt_total_engines == 70


def test_build_report_attaches_ai_summary(monkeypatch):
    cfg = config.load_config()
    cfg.anthropic_api_key = "test-anthropic-key"

    monkeypatch.setattr(
        "agent.reporter.generate_ai_summary",
        lambda report, api_key: "Consider reviewing the flagged binary." if api_key else None,
    )

    report = build_report(cfg)

    assert report.ai_summary == "Consider reviewing the flagged binary."


def test_build_report_leaves_ai_summary_unset_when_generator_returns_none(monkeypatch):
    cfg = config.load_config()
    cfg.anthropic_api_key = "test-anthropic-key"

    monkeypatch.setattr("agent.reporter.generate_ai_summary", lambda report, api_key: None)

    report = build_report(cfg)

    assert report.ai_summary is None
