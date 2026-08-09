"""
Optional VirusTotal hash-reputation lookups.

For every SHA-256 hash already computed locally by
agent/collectors/file_hashes.py, looks the hash up against VirusTotal's
public API and records how many antivirus engines flag it as malicious.

Only the hash itself is ever sent to VirusTotal - file contents never leave
the machine for this step.

Skipped entirely when no API key is configured (VIRUSTOTAL_API_KEY unset in
.env), so the scanner works fine without it.
"""
from __future__ import annotations

import time

import requests

from common.schemas import FileHashEntry

VT_API_BASE = "https://www.virustotal.com/api/v3/files"

# The VirusTotal public/free tier allows ~4 requests/minute. Spacing lookups
# this far apart keeps us under that without needing a sliding-window
# request counter.
DEFAULT_MIN_INTERVAL_SECONDS = 15.0
MAX_RETRIES_ON_RATE_LIMIT = 3


def _sleep(seconds: float) -> None:
    if seconds > 0:
        time.sleep(seconds)


def _lookup_hash(
    sha256: str,
    api_key: str,
    session: requests.Session,
    timeout: int,
) -> tuple[int | None, int | None, str | None]:
    """Looks up a single hash. Returns (malicious_count, total_engines, error)."""
    for attempt in range(MAX_RETRIES_ON_RATE_LIMIT + 1):
        try:
            response = session.get(
                f"{VT_API_BASE}/{sha256}",
                headers={"x-apikey": api_key},
                timeout=timeout,
            )
        except requests.RequestException as exc:
            return None, None, f"VirusTotal request failed: {exc}"

        if response.status_code == 429:
            if attempt >= MAX_RETRIES_ON_RATE_LIMIT:
                return None, None, "VirusTotal rate limit exceeded (429); gave up after retries"
            retry_after = response.headers.get("Retry-After")
            try:
                delay = float(retry_after) if retry_after else DEFAULT_MIN_INTERVAL_SECONDS
            except ValueError:
                delay = DEFAULT_MIN_INTERVAL_SECONDS
            _sleep(delay)
            continue

        if response.status_code == 404:
            return None, None, "Hash not found in VirusTotal"

        if response.status_code != 200:
            return None, None, f"VirusTotal returned HTTP {response.status_code}"

        try:
            stats = response.json()["data"]["attributes"]["last_analysis_stats"]
            malicious = int(stats.get("malicious", 0))
            total = sum(int(v) for v in stats.values())
        except (KeyError, TypeError, ValueError) as exc:
            return None, None, f"Unexpected VirusTotal response shape: {exc}"

        return malicious, total, None

    return None, None, "VirusTotal lookup failed"


def enrich_with_virustotal(
    file_hashes: list[FileHashEntry],
    api_key: str | None,
    *,
    min_interval_seconds: float = DEFAULT_MIN_INTERVAL_SECONDS,
    timeout: int = 30,
    session: requests.Session | None = None,
) -> list[FileHashEntry]:
    """Looks up every hashed file's SHA-256 against VirusTotal.

    Returns a new list (input entries are not mutated) with vt_malicious_count
    / vt_total_engines / vt_error filled in. Returns `file_hashes` unchanged,
    with no network calls, if `api_key` is falsy - this is what makes the
    VirusTotal step fully optional.
    """
    if not api_key:
        return file_hashes

    session = session or requests.Session()
    enriched: list[FileHashEntry] = []
    last_call: float | None = None

    for entry in file_hashes:
        if not entry.sha256:
            enriched.append(entry)
            continue

        if last_call is not None:
            elapsed = time.monotonic() - last_call
            _sleep(min_interval_seconds - elapsed)
        last_call = time.monotonic()

        malicious, total, error = _lookup_hash(entry.sha256, api_key, session, timeout)
        enriched.append(
            entry.model_copy(
                update={
                    "vt_malicious_count": malicious,
                    "vt_total_engines": total,
                    "vt_error": error,
                }
            )
        )

    return enriched
