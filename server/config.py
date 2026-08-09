"""
Server-side configuration, loaded from a .env file (never hardcoded).

See .env.example for the full list of supported variables.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()


@dataclass
class ServerConfig:
    api_key: str
    admin_email: str

    smtp_host: str
    smtp_port: int
    smtp_username: str
    smtp_password: str
    smtp_use_tls: bool
    smtp_from_address: str

    storage_dir: str


def load_config() -> ServerConfig:
    api_key = os.getenv("API_KEY", "")
    admin_email = os.getenv("ADMIN_EMAIL", "")

    if not api_key:
        raise RuntimeError("API_KEY is not set in .env - agents authenticate to this server with it.")
    if not admin_email:
        raise RuntimeError("ADMIN_EMAIL is not set in .env - every report is emailed to this address.")

    smtp_username = os.getenv("SMTP_USERNAME", "")

    return ServerConfig(
        api_key=api_key,
        admin_email=admin_email,
        smtp_host=os.getenv("SMTP_HOST", ""),
        smtp_port=int(os.getenv("SMTP_PORT", "587")),
        smtp_username=smtp_username,
        smtp_password=os.getenv("SMTP_PASSWORD", ""),
        smtp_use_tls=os.getenv("SMTP_USE_TLS", "true").lower() == "true",
        smtp_from_address=os.getenv("SMTP_FROM_ADDRESS", smtp_username),
        storage_dir=os.getenv("STORAGE_DIR", "./reports"),
    )
