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
