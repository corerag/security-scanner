"""
Agent-side configuration, loaded from a .env file (never hardcoded).

See .env.example for the full list of supported variables.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

from dotenv import load_dotenv

load_dotenv()


@dataclass
class AgentConfig:
    server_url: str
    api_key: str
    owner_email: str
    owner_name: str | None = None
    notes: str | None = None
    extra_hash_paths: list[str] = field(default_factory=list)
    hash_process_executables: bool = False
    request_timeout: int = 30


def _split_csv(value: str | None) -> list[str]:
    if not value:
        return []
    return [v.strip() for v in value.split(",") if v.strip()]


def load_config() -> AgentConfig:
    server_url = os.getenv("SERVER_URL", "http://127.0.0.1:8000")
    api_key = os.getenv("API_KEY", "")
    owner_email = os.getenv("OWNER_EMAIL", "")

    if not api_key:
        raise RuntimeError(
            "API_KEY is not set. Add it to your .env file - it must match the "
            "server's API_KEY so the server can authenticate this agent."
        )
    if not owner_email:
        raise RuntimeError(
            "OWNER_EMAIL is not set. Add it to your .env file - this is the "
            "address of the person who owns/uses the scanned machine, and the "
            "server will email the report there."
        )

    return AgentConfig(
        server_url=server_url.rstrip("/"),
        api_key=api_key,
        owner_email=owner_email,
        owner_name=os.getenv("OWNER_NAME") or None,
        notes=os.getenv("SCAN_NOTES") or None,
        extra_hash_paths=_split_csv(os.getenv("EXTRA_HASH_PATHS")),
        hash_process_executables=os.getenv("HASH_PROCESS_EXECUTABLES", "false").lower() == "true",
        request_timeout=int(os.getenv("REQUEST_TIMEOUT_SECONDS", "30")),
    )
