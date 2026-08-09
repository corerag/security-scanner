"""
Optional AI triage layer.

After a scan report is fully assembled, sends its structured findings -
process names, network connection info, VirusTotal detection counts, and
file hashes - to Claude and asks for a plain-English summary a human can
use to decide what deserves a closer look. No file contents are ever
included; there are none in the report to begin with.

The model interprets and advises. It never classifies anything as
definitively malicious and never recommends or implies an automated
action - see SYSTEM_PROMPT below for the exact framing sent on every
request.

Skipped entirely when ANTHROPIC_API_KEY is not configured, and any failure
(network error, API error, refusal) falls back to no summary rather than
aborting the scan.
"""
from __future__ import annotations

import json
import sys

import anthropic

from common.schemas import ScanReport

DEFAULT_MODEL = "claude-opus-5"

# Caps keep the request small and bounded even on a machine with an
# unusually large number of processes/connections/hashed files.
_MAX_PROCESSES = 200
_MAX_CONNECTIONS = 200
_MAX_FILE_HASHES = 200

SYSTEM_PROMPT = (
    "You are a triage assistant helping a human security analyst read a local "
    "system scan report. You are given structured findings only: running "
    "process names, network connection info, file SHA-256 hashes with any "
    "VirusTotal detection counts, and persistence-mechanism counts. No file "
    "contents are ever included - only this metadata.\n\n"
    "Your job is to INTERPRET and ADVISE, not to decide. Explain in plain "
    "English what was found and why it might matter, and point out anything "
    "a human should look at more closely and why. Do not state that "
    "anything IS malicious, do not give a final verdict on the machine's "
    "safety, and do not recommend or imply any automated action (never say "
    "things like 'this file should be deleted' or 'block this connection'). "
    "Frame every observation as something for the analyst to verify "
    "themselves - use language like 'worth checking', 'may be worth "
    "reviewing', or 'consider verifying', never 'is', 'confirmed', or a bare "
    "'malicious'. If nothing stands out, say so plainly and briefly. Keep "
    "the summary under 200 words."
)


def _build_findings(report: ScanReport) -> dict:
    """Extracts only the fields relevant to triage. Never includes file
    contents - only paths, hashes, and metadata already in the report."""
    return {
        "hostname": report.hostname,
        "os": f"{report.os_platform} {report.os_version}",
        "processes": [
            {"pid": p.pid, "name": p.name, "username": p.username}
            for p in report.processes[:_MAX_PROCESSES]
        ],
        "network_connections": [
            {
                "local_address": c.local_address,
                "remote_address": c.remote_address,
                "status": c.status,
                "process_name": c.process_name,
            }
            for c in report.network_connections[:_MAX_CONNECTIONS]
        ],
        "persistence": {
            "registry_run_key_count": len(report.persistence.registry_run_keys),
            "scheduled_task_count": len(report.persistence.scheduled_tasks),
            "startup_item_count": len(report.persistence.startup_items),
        },
        "file_hashes": [
            {
                "path": f.path,
                "sha256": f.sha256,
                "exists": f.exists,
                "vt_malicious_count": f.vt_malicious_count,
                "vt_total_engines": f.vt_total_engines,
            }
            for f in report.file_hashes[:_MAX_FILE_HASHES]
        ],
    }


def generate_ai_summary(
    report: ScanReport,
    api_key: str | None,
    *,
    model: str = DEFAULT_MODEL,
    client: anthropic.Anthropic | None = None,
) -> str | None:
    """Returns a plain-English triage summary, or None if AI triage is
    unconfigured or the call fails for any reason."""
    if not api_key:
        return None

    findings = _build_findings(report)
    user_content = (
        "Structured scan findings (JSON, metadata only - no file contents):\n\n"
        + json.dumps(findings, indent=2, default=str)
    )

    try:
        client = client or anthropic.Anthropic(api_key=api_key)
        response = client.messages.create(
            model=model,
            max_tokens=1024,
            system=SYSTEM_PROMPT,
            output_config={"effort": "medium"},
            messages=[{"role": "user", "content": user_content}],
        )
    except Exception as exc:
        print(f"AI triage summary skipped: {exc}", file=sys.stderr)
        return None

    if getattr(response, "stop_reason", None) == "refusal":
        return None

    text = "".join(block.text for block in response.content if block.type == "text").strip()
    return text or None
