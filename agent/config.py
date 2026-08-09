"""
Agent-side configuration, loaded from a .env file (never hardcoded).

See .env.example for the full list of supported variables.
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field

from dotenv import load_dotenv


def _default_dotenv_path() -> str:
    """
    Resolve .env relative to the running executable/script rather than the
    current working directory. This matters for the standalone PyInstaller
    build: double-clicking an .exe on a USB drive, or launching it from a
    shortcut, doesn't reliably set the working directory to the folder the
    .exe lives in, but the .env file is expected to sit right next to it.
    """
    if getattr(sys, "frozen", False):
        base_dir = os.path.dirname(sys.executable)
    else:
        # Running from source: resolve relative to the project root (two
        # levels up from this file, agent/config.py -> project root).
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_dir, ".env")


load_dotenv(_default_dotenv_path())

VALID_DELIVERY_MODES = ("server", "direct_email")


@dataclass
class AgentConfig:
    delivery_mode: str  # "server" or "direct_email"
    owner_email: str
    owner_name: str | None = None
    notes: str | None = None
    extra_hash_paths: list[str] = field(default_factory=list)
    hash_process_executables: bool = False
    request_timeout: int = 30

    # Optional VirusTotal hash-reputation lookups (agent/virustotal.py).
    # Lookups are skipped entirely when this is unset.
    virustotal_api_key: str | None = None

    # Optional AI triage summary via the Anthropic API (agent/ai_triage.py).
    # Skipped entirely when this is unset.
    anthropic_api_key: str | None = None

    # "server" mode
    server_url: str = "http://127.0.0.1:8000"
    api_key: str = ""

    # "direct_email" mode - same variable names/values as the server's own
    # .env, so a portable agent + .env pair is self-contained.
    admin_email: str | None = None
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_use_tls: bool = True
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_from_address: str = ""


def _split_csv(value: str | None) -> list[str]:
    if not value:
        return []
    return [v.strip() for v in value.split(",") if v.strip()]


def load_config() -> AgentConfig:
    delivery_mode = os.getenv("DELIVERY_MODE", "server").strip().lower()
    if delivery_mode not in VALID_DELIVERY_MODES:
        raise RuntimeError(
            f"DELIVERY_MODE must be one of {VALID_DELIVERY_MODES}, got {delivery_mode!r}."
        )

    owner_email = os.getenv("OWNER_EMAIL", "")
    if not owner_email:
        raise RuntimeError(
            "OWNER_EMAIL is not set. Add it to your .env file - this is the "
            "address of the person who owns/uses the scanned machine."
        )

    server_url = os.getenv("SERVER_URL", "http://127.0.0.1:8000")
    api_key = os.getenv("API_KEY", "")
    smtp_username = os.getenv("SMTP_USERNAME", "")
    admin_email = os.getenv("ADMIN_EMAIL") or None
    smtp_host = os.getenv("SMTP_HOST", "")

    if delivery_mode == "server" and not api_key:
        raise RuntimeError(
            "API_KEY is not set. Add it to your .env file - it must match the "
            "server's API_KEY so the server can authenticate this agent. "
            "(Set DELIVERY_MODE=direct_email instead if there is no report server.)"
        )

    if delivery_mode == "direct_email":
        if not admin_email:
            raise RuntimeError("ADMIN_EMAIL is required in .env when DELIVERY_MODE=direct_email.")
        if not smtp_host:
            raise RuntimeError("SMTP_HOST is required in .env when DELIVERY_MODE=direct_email.")

    return AgentConfig(
        delivery_mode=delivery_mode,
        owner_email=owner_email,
        owner_name=os.getenv("OWNER_NAME") or None,
        notes=os.getenv("SCAN_NOTES") or None,
        extra_hash_paths=_split_csv(os.getenv("EXTRA_HASH_PATHS")),
        hash_process_executables=os.getenv("HASH_PROCESS_EXECUTABLES", "false").lower() == "true",
        request_timeout=int(os.getenv("REQUEST_TIMEOUT_SECONDS", "30")),
        virustotal_api_key=os.getenv("VIRUSTOTAL_API_KEY") or None,
        anthropic_api_key=os.getenv("ANTHROPIC_API_KEY") or None,
        server_url=server_url.rstrip("/"),
        api_key=api_key,
        admin_email=admin_email,
        smtp_host=smtp_host,
        smtp_port=int(os.getenv("SMTP_PORT", "587")),
        smtp_use_tls=os.getenv("SMTP_USE_TLS", "true").lower() == "true",
        smtp_username=smtp_username,
        smtp_password=os.getenv("SMTP_PASSWORD", ""),
        smtp_from_address=os.getenv("SMTP_FROM_ADDRESS", smtp_username) or smtp_username,
    )
