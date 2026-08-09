"""Collects information about currently running processes via psutil."""
from __future__ import annotations

from datetime import datetime, timezone

import psutil

from common.schemas import ProcessInfo

_PROC_ATTRS = ["pid", "ppid", "name", "exe", "cmdline", "username", "status", "create_time"]


def collect_processes() -> list[ProcessInfo]:
    results: list[ProcessInfo] = []
    for proc in psutil.process_iter(_PROC_ATTRS):
        try:
            info = proc.info
            create_time = info.get("create_time")
            results.append(
                ProcessInfo(
                    pid=info.get("pid"),
                    ppid=info.get("ppid"),
                    name=info.get("name") or "",
                    exe=info.get("exe") or None,
                    cmdline=" ".join(info.get("cmdline") or []) or None,
                    username=info.get("username") or None,
                    status=info.get("status") or None,
                    create_time=(
                        datetime.fromtimestamp(create_time, tz=timezone.utc) if create_time else None
                    ),
                )
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            # Processes can exit mid-scan, or be inaccessible without elevated
            # rights. Skip rather than fail the whole scan.
            continue
    return results
