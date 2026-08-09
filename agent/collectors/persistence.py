"""
Collects common Windows persistence locations:
  - Registry "Run" / "RunOnce" keys (HKLM + HKCU, including WOW6432Node)
  - Scheduled tasks (via `schtasks`)
  - Startup folder shortcuts/files (per-user and all-users)

On non-Windows platforms these all return empty results rather than
raising, so the rest of the scan can still run.
"""
from __future__ import annotations

import csv
import io
import os
import platform
import subprocess

from common.schemas import PersistenceReport, RegistryRunKeyEntry, ScheduledTaskEntry, StartupItemEntry

IS_WINDOWS = platform.system() == "Windows"

if IS_WINDOWS:
    import winreg

    _RUN_KEY_LOCATIONS = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    ]

    def _hive_name(hive) -> str:
        return {
            winreg.HKEY_LOCAL_MACHINE: "HKLM",
            winreg.HKEY_CURRENT_USER: "HKCU",
        }.get(hive, str(hive))


def collect_registry_run_keys() -> list[RegistryRunKeyEntry]:
    if not IS_WINDOWS:
        return []

    entries: list[RegistryRunKeyEntry] = []
    for hive, key_path in _RUN_KEY_LOCATIONS:
        try:
            with winreg.OpenKey(hive, key_path) as key:
                index = 0
                while True:
                    try:
                        value_name, value_data, _value_type = winreg.EnumValue(key, index)
                    except OSError:
                        break
                    entries.append(
                        RegistryRunKeyEntry(
                            hive=_hive_name(hive),
                            key_path=key_path,
                            value_name=value_name,
                            value_data=str(value_data),
                        )
                    )
                    index += 1
        except FileNotFoundError:
            continue
        except OSError:
            continue
    return entries


def collect_scheduled_tasks() -> list[ScheduledTaskEntry]:
    if not IS_WINDOWS:
        return []

    tasks: list[ScheduledTaskEntry] = []
    try:
        proc = subprocess.run(
            ["schtasks", "/query", "/fo", "CSV", "/v"],
            capture_output=True,
            text=True,
            timeout=60,
            check=True,
        )
    except (subprocess.SubprocessError, OSError, FileNotFoundError):
        return tasks

    reader = csv.DictReader(io.StringIO(proc.stdout))
    for row in reader:
        task_name = row.get("TaskName")
        # schtasks /v repeats the header for every "page"; skip stray header rows.
        if not task_name or task_name == "TaskName":
            continue
        tasks.append(
            ScheduledTaskEntry(
                name=task_name,
                status=row.get("Status"),
                next_run_time=row.get("Next Run Time"),
                command=row.get("Task To Run"),
                author=row.get("Author"),
                run_as_user=row.get("Run As User"),
            )
        )
    return tasks


def _startup_folders() -> list[tuple[str, str]]:
    folders: list[tuple[str, str]] = []
    appdata = os.environ.get("APPDATA")
    if appdata:
        folders.append(("user", os.path.join(appdata, r"Microsoft\Windows\Start Menu\Programs\Startup")))
    programdata = os.environ.get("PROGRAMDATA")
    if programdata:
        folders.append(("common", os.path.join(programdata, r"Microsoft\Windows\Start Menu\Programs\Startup")))
    return folders


def collect_startup_items() -> list[StartupItemEntry]:
    if not IS_WINDOWS:
        return []

    items: list[StartupItemEntry] = []
    for scope, folder in _startup_folders():
        if not os.path.isdir(folder):
            continue
        for filename in os.listdir(folder):
            full_path = os.path.join(folder, filename)
            if filename.lower() == "desktop.ini":
                continue
            items.append(StartupItemEntry(location=scope, path=full_path, name=filename))
    return items


def collect_persistence() -> PersistenceReport:
    return PersistenceReport(
        registry_run_keys=collect_registry_run_keys(),
        scheduled_tasks=collect_scheduled_tasks(),
        startup_items=collect_startup_items(),
    )
