"""Small shared helpers used by more than one collector."""
from __future__ import annotations

import re


def extract_executable_path(command: str | None) -> str | None:
    """
    Best-effort extraction of an executable path from a command line pulled
    out of a registry Run key, a scheduled task action, or similar.

    Handles the common cases:
      - '"C:\\Program Files\\App\\app.exe" --flag'  -> C:\\Program Files\\App\\app.exe
      - 'C:\\Windows\\App\\app.exe /silent'          -> C:\\Windows\\App\\app.exe
      - 'rundll32.exe some.dll,Entry'               -> rundll32.exe
    """
    if not command:
        return None
    command = command.strip()
    if not command:
        return None

    if command.startswith('"'):
        match = re.match(r'"([^"]+)"', command)
        if match:
            return match.group(1).strip()

    match = re.search(r"^(.*?\.exe)\b", command, re.IGNORECASE)
    if match:
        return match.group(1).strip()

    # Fall back to the first whitespace-delimited token.
    return command.split(" ")[0].strip() or None
