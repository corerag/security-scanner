"""
Shared Pydantic models used by both the local agent (to build a report) and
the FastAPI server (to validate an incoming report). Keeping these in one
place means the two sides can never silently drift apart.
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr, Field


# --------------------------------------------------------------------------
# Processes
# --------------------------------------------------------------------------
class ProcessInfo(BaseModel):
    pid: int
    ppid: Optional[int] = None
    name: str
    exe: Optional[str] = None
    cmdline: Optional[str] = None
    username: Optional[str] = None
    status: Optional[str] = None
    create_time: Optional[datetime] = None


# --------------------------------------------------------------------------
# Network
# --------------------------------------------------------------------------
class NetworkConnectionInfo(BaseModel):
    fd: Optional[int] = None
    family: Optional[str] = None
    type: Optional[str] = None
    local_address: Optional[str] = None
    remote_address: Optional[str] = None
    status: Optional[str] = None
    pid: Optional[int] = None
    process_name: Optional[str] = None


# --------------------------------------------------------------------------
# Persistence
# --------------------------------------------------------------------------
class RegistryRunKeyEntry(BaseModel):
    hive: str
    key_path: str
    value_name: str
    value_data: Optional[str] = None


class ScheduledTaskEntry(BaseModel):
    name: str
    status: Optional[str] = None
    next_run_time: Optional[str] = None
    command: Optional[str] = None
    author: Optional[str] = None
    run_as_user: Optional[str] = None


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
    sha256: Optional[str] = None
    size_bytes: Optional[int] = None
    exists: bool = True
    error: Optional[str] = None


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
    owner_name: Optional[str] = None
    notes: Optional[str] = None

    processes: list[ProcessInfo] = Field(default_factory=list)
    network_connections: list[NetworkConnectionInfo] = Field(default_factory=list)
    persistence: PersistenceReport = Field(default_factory=PersistenceReport)
    file_hashes: list[FileHashEntry] = Field(default_factory=list)


class ReportAck(BaseModel):
    scan_id: str
    stored_at: str
    email_sent: bool
