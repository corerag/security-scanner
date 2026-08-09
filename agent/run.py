"""
CLI entry point for the local scanning agent.

Run this ON the machine you want to scan and have explicit authorization
to inspect. It builds a ScanReport and delivers it one of two ways,
controlled by DELIVERY_MODE in .env:

  - "server" (default): POSTs the report to the FastAPI report server,
    which emails a summary to the configured admin and machine-owner
    addresses.
  - "direct_email": emails the report straight from the agent via SMTP,
    for machines that can't reach the report server (e.g. a portable
    agent run from a USB drive). See .env.example for the SMTP settings
    this mode needs.

Usage:
    python -m agent.run --yes
    python -m agent.run --dry-run --output last_scan.json
"""
from __future__ import annotations

import argparse
import json
import sys

import requests

from . import config, direct_email
from .reporter import build_report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Consent-based local security scan agent.")
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Confirm you are authorized to scan this machine and skip the interactive prompt.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Build the report but do not send/email it.",
    )
    parser.add_argument(
        "--output",
        help="Optional file path to also save the full report as JSON.",
    )
    return parser.parse_args()


def confirm_consent(auto_yes: bool) -> bool:
    if auto_yes:
        return True
    print("This tool inspects running processes, network connections, persistence")
    print("locations (scheduled tasks, registry Run keys, startup folders), and")
    print("file hashes on THIS machine, and sends/emails the results off this machine.")
    answer = input("Do you have authorization to scan this machine? [y/N]: ").strip().lower()
    return answer in ("y", "yes")


def _submit_to_server(payload: dict, cfg: config.AgentConfig) -> None:
    try:
        response = requests.post(
            f"{cfg.server_url}/api/v1/reports",
            json=payload,
            headers={"X-API-Key": cfg.api_key},
            timeout=cfg.request_timeout,
        )
        response.raise_for_status()
    except requests.RequestException as exc:
        print(f"Failed to submit report to server: {exc}", file=sys.stderr)
        sys.exit(1)
    print(f"Report submitted successfully: {response.json()}")


def main() -> None:
    args = parse_args()

    if not confirm_consent(args.yes):
        print("Consent not confirmed. Aborting scan.")
        sys.exit(1)

    try:
        cfg = config.load_config()
    except RuntimeError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        sys.exit(1)

    if cfg.delivery_mode == "direct_email":
        print(f"Scanning host... report will be emailed directly to {cfg.admin_email} and the owner.")
    else:
        print(f"Scanning host... report will be sent to {cfg.server_url} for owner <{cfg.owner_email}>.")

    report = build_report(cfg)
    payload = json.loads(report.model_dump_json())

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        print(f"Report saved to {args.output}")

    if args.dry_run:
        print("Dry run - report was not sent or emailed.")
        return

    if cfg.delivery_mode == "direct_email":
        try:
            recipients = direct_email.send_report_directly(report, cfg)
        except Exception as exc:
            print(f"Failed to email report: {exc}", file=sys.stderr)
            sys.exit(1)
        print(f"Report emailed directly to: {', '.join(recipients)}")
    else:
        _submit_to_server(payload, cfg)


if __name__ == "__main__":
    main()
