"""
Shared Pydantic models used by both the local agent (to build a report) and
the FastAPI server (to validate an incoming report). Keeping these in one
place means the two sides can never silently drift apart.
"""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, EmailStr, Field


# --------------------------------------------------------------------------
# Processes
# --------------------------------------------------------------------------
class ProcessInfo(BaseModel):
    pid: int
    ppid: int | None = None
    name: str
    exe: str | None = None
    cmdline: str | None = None
    username: str | None = None
    status: str | None = None
    create_time: datetime | None = None


# --------------------------------------------------------------------------
# Network
# --------------------------------------------------------------------------
class NetworkConnectionInfo(BaseModel):
    fd: int | None = None
    family: str | None = None
    type: str | None = None
    local_address: str | None = None
    remote_address: str | None = None
    status: str | None = None
    pid: int | None = None
    process_name: str | None = None


# --------------------------------------------------------------------------
# Persistence
# --------------------------------------------------------------------------
class RegistryRunKeyEntry(BaseModel):
    hive: str
    key_path: str
    value_name: str
    value_data: str | None = None


class ScheduledTaskEntry(BaseModel):
    name: str
    status: str | None = None
    next_run_time: str | None = None
    command: str | None = None
    author: str | None = None
    run_as_user: str | None = None


class StartupItemEntry(BaseModel):
    location: str  # "user" or "common"
    path: str
    name: str


class PersistenceReport(BaseModel):
    registry_run_keys: list[RegistryRunKeyEntry] = Field(default_factory=list)
    scheduled_tasks: list[ScheduledTaskEntry] = Field(default_factory=list)
    startup_items: list[StartupItemEntry] = Field(default_factory=list)


# --------------------------------------------------------------------------
# File hashes
# --------------------------------------------------------------------------
class FileHashEntry(BaseModel):
    path: str
    sha256: str | None = None
    size_bytes: int | None = None
    exists: bool = True
    error: str | None = None

    # Optional VirusTotal enrichment (agent/virustotal.py). Left as None
    # when VIRUSTOTAL_API_KEY is not configured or the hash wasn't looked up.
    vt_malicious_count: int | None = None
    vt_total_engines: int | None = None
    vt_error: str | None = None


# --------------------------------------------------------------------------
# Top-level report
# --------------------------------------------------------------------------
class ScanReport(BaseModel):
    scan_id: str
    hostname: str
    os_platform: str
    os_version: str
    agent_version: str

    scan_started_at: datetime
    scan_completed_at: datetime

    owner_email: EmailStr
    owner_name: str | None = None
    notes: str | None = None

    # Optional plain-English triage summary from an LLM (agent/ai_triage.py).
    # Advisory only - explains findings for a human to review, never a
    # malicious/benign determination. None when ANTHROPIC_API_KEY is not
    # configured or the summary call failed.
    ai_summary: str | None = None

    processes: list[ProcessInfo] = Field(default_factory=list)
    network_connections: list[NetworkConnectionInfo] = Field(default_factory=list)
    persistence: PersistenceReport = Field(default_factory=PersistenceReport)
    file_hashes: list[FileHashEntry] = Field(default_factory=list)


class ReportAck(BaseModel):
    scan_id: str
    stored_at: str
    email_sent: bool
