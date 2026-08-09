"""Collects active network connections and the owning process, via psutil."""
from __future__ import annotations

import psutil

from common.schemas import NetworkConnectionInfo


def _format_addr(addr) -> str | None:
    if not addr:
        return None
    return f"{addr.ip}:{addr.port}"


def collect_network_connections() -> list[NetworkConnectionInfo]:
    try:
        connections = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        # On most systems, listing *all* connections (not just this
        # process's own) requires elevated privileges. Return an empty list
        # rather than crashing the whole scan; the README documents this.
        return []

    process_name_cache: dict[int, str | None] = {}
    results: list[NetworkConnectionInfo] = []

    for conn in connections:
        process_name = None
        if conn.pid:
            if conn.pid not in process_name_cache:
                try:
                    process_name_cache[conn.pid] = psutil.Process(conn.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    process_name_cache[conn.pid] = None
            process_name = process_name_cache[conn.pid]

        results.append(
            NetworkConnectionInfo(
                fd=conn.fd if conn.fd not in (-1, None) else None,
                family=str(conn.family),
                type=str(conn.type),
                local_address=_format_addr(conn.laddr),
                remote_address=_format_addr(conn.raddr),
                status=conn.status,
                pid=conn.pid,
                process_name=process_name,
            )
        )
    return results
