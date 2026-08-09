"""
Computes SHA-256 hashes for a given set of file paths, so a later
comparison run (or a human) can detect that a persistence target or
watched binary has changed.
"""
from __future__ import annotations

import hashlib
import os

from common.schemas import FileHashEntry

_CHUNK_SIZE = 1024 * 1024  # 1 MiB


def _sha256_of_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(_CHUNK_SIZE):
            digest.update(chunk)
    return digest.hexdigest()


def _normalize(raw_path: str) -> str:
    return os.path.expandvars(os.path.expanduser(raw_path.strip().strip('"')))


def hash_paths(paths: list[str]) -> list[FileHashEntry]:
    """Hash each unique, existing file in `paths`. Missing files and read
    errors are reported as entries rather than raised, so one bad path
    doesn't abort the whole scan."""
    seen: set[str] = set()
    results: list[FileHashEntry] = []

    for raw_path in paths:
        if not raw_path:
            continue
        path = _normalize(str(raw_path))
        if not path or path in seen:
            continue
        seen.add(path)

        if not os.path.isfile(path):
            results.append(FileHashEntry(path=path, exists=False, error="File not found"))
            continue

        try:
            results.append(
                FileHashEntry(
                    path=path,
                    sha256=_sha256_of_file(path),
                    size_bytes=os.path.getsize(path),
                    exists=True,
                )
            )
        except OSError as exc:
            results.append(FileHashEntry(path=path, exists=True, error=str(exc)))

    return results
