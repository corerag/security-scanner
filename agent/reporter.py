"""Builds a single ScanReport by running every collector."""
from __future__ import annotations

import platform
import socket
import uuid
from datetime import datetime, timezone

from common.schemas import PersistenceReport, ScanReport

from . import config
from .collectors.file_hashes import hash_paths
from .collectors.network import collect_network_connections
from .collectors.persistence import collect_persistence
from .collectors.processes import collect_processes
from .collectors.utils import extract_executable_path

AGENT_VERSION = "1.0.0"


def _gather_hash_targets(persistence: PersistenceReport, extra_paths: list[str]) -> list[str]:
    """Union of user-configured paths plus every executable referenced by a
    persistence mechanism, so those binaries get hashed automatically."""
    targets: set[str] = set(extra_paths)

    for entry in persistence.registry_run_keys:
        path = extract_executable_path(entry.value_data)
        if path:
            targets.add(path)

    for entry in persistence.scheduled_tasks:
        path = extract_executable_path(entry.command)
        if path:
            targets.add(path)

    for entry in persistence.startup_items:
        targets.add(entry.path)

    return sorted(targets)


def build_report(cfg: config.AgentConfig | None = None) -> ScanReport:
    cfg = cfg or config.load_config()

    started_at = datetime.now(timezone.utc)

    processes = collect_processes()
    network_connections = collect_network_connections()
    persistence = collect_persistence()

    hash_targets = _gather_hash_targets(persistence, cfg.extra_hash_paths)
    if cfg.hash_process_executables:
        hash_targets = sorted(set(hash_targets) | {p.exe for p in processes if p.exe})
    file_hashes = hash_paths(hash_targets)

    completed_at = datetime.now(timezone.utc)

    return ScanReport(
        scan_id=str(uuid.uuid4()),
        hostname=socket.gethostname(),
        os_platform=platform.system(),
        os_version=platform.version(),
        agent_version=AGENT_VERSION,
        scan_started_at=started_at,
        scan_completed_at=completed_at,
        owner_email=cfg.owner_email,
        owner_name=cfg.owner_name,
        notes=cfg.notes,
        processes=processes,
        network_connections=network_connections,
        persistence=persistence,
        file_hashes=file_hashes,
    )
