"""Persists every received report to disk as JSON for later reference/audit."""
from __future__ import annotations

import os
import re

from common.schemas import ScanReport

_UNSAFE_CHARS = re.compile(r"[^A-Za-z0-9_.-]+")


def _safe_component(value: str) -> str:
    return _UNSAFE_CHARS.sub("_", value)


def save_report(report: ScanReport, storage_dir: str) -> str:
    os.makedirs(storage_dir, exist_ok=True)

    timestamp = report.scan_completed_at.strftime("%Y%m%dT%H%M%SZ")
    filename = f"{timestamp}_{_safe_component(report.hostname)}_{report.scan_id}.json"
    path = os.path.join(storage_dir, filename)

    with open(path, "w", encoding="utf-8") as f:
        f.write(report.model_dump_json(indent=2))

    return path
