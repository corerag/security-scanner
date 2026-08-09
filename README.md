# Consent-Based Security Scanner

[![CI](https://github.com/corerag/security-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/corerag/security-scanner/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/github/license/corerag/security-scanner)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/server-FastAPI-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

A small scanning tool for **machines you own or are explicitly authorized
to scan**:

1. **Agent** (`agent/`) — runs locally on the target machine. Collects
   running processes, active network connections, common persistence
   locations (registry `Run`/`RunOnce` keys, scheduled tasks, startup
   folders), and SHA-256 hashes of the executables it finds, then
   delivers the result one of two ways (`DELIVERY_MODE` in `.env`):
   - **`server`** (default) — submits the report to the FastAPI report server.
   - **`direct_email`** — emails the report itself via SMTP, no server
     required. This is what makes the agent **portable**: pack it onto a
     USB drive as a standalone `.exe` (see [Portable agent](#portable-agent-usb--no-server) below)
     and run it, with consent, on a machine that can't reach your server.
2. **Server** (`server/`) — a FastAPI service that receives reports from
   agents in `server` mode, stores them as JSON, and emails a summary to
   **two** addresses: yours (the admin) and the scanned machine owner's.

⚠️ **Only run the agent against systems you own or have explicit written
authorization to scan.** It requires interactive confirmation (or an
explicit `--yes` flag) before every scan for exactly this reason.

## How it works

```
 [ agent/run.py ]  --collects-->  ProcessInfo, NetworkConnectionInfo,
        |                          PersistenceReport, FileHashEntry
        |  builds common.schemas.ScanReport
        |
        +-- DELIVERY_MODE=server -------+   +-- DELIVERY_MODE=direct_email --+
        |   POST /api/v1/reports        |   |   builds + sends the email     |
        |   (X-API-Key header)          |   |   itself via SMTP              |
        v                                |   v (common/email_report.py)
 [ server/main.py, FastAPI ]             |  no server involved
        |  validates report (pydantic)  |
        |  saves JSON to STORAGE_DIR    |
        |  emails via                   |
        |    server/email_service.py ---+
        v
   two inboxes: yours (ADMIN_EMAIL), and the machine owner's (owner_email)
```

## Project layout

```
security-scanner/
├── .env.example         # copy to .env and fill in real values
├── requirements.txt / requirements-dev.txt
├── agent_entry.py        # PyInstaller entry point (see "Portable agent" below)
├── common/
│   ├── schemas.py          # shared Pydantic models (agent <-> server contract)
│   └── email_report.py      # builds/sends the report email (used by server AND agent)
├── agent/
│   ├── config.py         # reads agent-side settings from .env (incl. DELIVERY_MODE)
│   ├── reporter.py        # orchestrates collectors into a ScanReport
│   ├── run.py               # CLI entry point (consent prompt, dispatches by delivery mode)
│   ├── direct_email.py        # DELIVERY_MODE=direct_email: emails the report directly
│   └── collectors/
│       ├── processes.py     # running processes (psutil)
│       ├── network.py        # active network connections (psutil)
│       ├── persistence.py     # registry Run keys, scheduled tasks, startup folders
│       ├── file_hashes.py      # SHA-256 hashing of discovered/watched files
│       └── utils.py             # command-line -> executable path extraction
├── server/
│   ├── config.py         # reads server-side settings from .env
│   ├── storage.py          # saves reports as JSON
│   ├── email_service.py     # thin wrapper around common/email_report.py
│   └── main.py                # FastAPI app / HTTP endpoints
├── tests/                # pytest suite (schemas, collectors, reporter, server)
└── .github/workflows/ci.yml   # lint (ruff) + test (pytest) on push/PR
```

Credentials (the shared API key, SMTP username/password, email addresses)
live only in `.env`, loaded via `python-dotenv`. Nothing is hardcoded.
`.env` is git-ignored; commit only `.env.example`.

## Setup

### 1. Prerequisites

- Python 3.10 or later. On this machine, Python isn't currently
  installed (only the Microsoft Store app-execution alias exists).
  Install it from https://www.python.org/downloads/ (check **"Add
  python.exe to PATH"** during setup) or via `winget install Python.Python.3.12`,
  then open a new terminal.
- An SMTP account to send mail from (e.g., Gmail with an **App Password**,
  or any other SMTP provider). Gmail requires 2FA enabled and an App
  Password — your normal password will not work.

### 2. Install dependencies

From the `security-scanner` directory:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 3. Configure `.env`

```powershell
copy .env.example .env
notepad .env
```

Fill in at minimum:
- `DELIVERY_MODE` — `server` (default, needs the FastAPI server below) or
  `direct_email` (agent emails the report itself; see
  [Portable agent](#portable-agent-usb--no-server)).
- `OWNER_EMAIL` — the address of whoever owns the machine being scanned
  (can be the same as `ADMIN_EMAIL` if you're scanning your own machine).
- `ADMIN_EMAIL` — your address.
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD` — your SMTP
  provider's settings (used by the server, and by the agent in
  `direct_email` mode).
- `API_KEY` — a random shared secret (generate with
  `python -c "import secrets; print(secrets.token_urlsafe(32))"`); only
  needed in `server` mode, must match between agent and server.
- `SERVER_URL` — where the agent should send reports in `server` mode
  (defaults to `http://127.0.0.1:8000` for running both parts on the same
  machine).

If the agent and server run on different machines, each needs its own
`.env` (copy the project or just the relevant files), and they must share
the same `API_KEY`.

## Running it

### Start the report server

```powershell
python -m uvicorn server.main:app --host 0.0.0.0 --port 8000
```

(Using `python -m uvicorn` rather than the bare `uvicorn` command ensures
the project root is on `sys.path` so `server` and `common` can be
imported, regardless of how your shell resolves the `uvicorn` executable.)

Check it's up: open `http://127.0.0.1:8000/api/v1/health` (or from
another terminal, `Invoke-RestMethod http://127.0.0.1:8000/api/v1/health`) —
you should see `{"status": "ok"}`. Interactive API docs are at
`http://127.0.0.1:8000/docs`.

### Run the agent

In a second terminal (with the venv activated):

```powershell
python -m agent.run
```

You'll be asked to confirm you're authorized to scan the machine, then
the report is built and submitted. Useful flags:

- `python -m agent.run --yes` — skip the interactive confirmation
  (for scripted/scheduled runs where you've already confirmed authorization).
- `python -m agent.run --dry-run --output scan.json` — build and save the
  report locally without sending it anywhere, useful for a first look.
- Reading Windows registry `Run` keys, `schtasks`, and all users' network
  connections works best from an **elevated (Administrator)** PowerShell
  prompt; without elevation some entries may be silently skipped
  (`psutil` and `winreg` calls degrade gracefully rather than failing).

If everything is configured correctly, within a few seconds both
`ADMIN_EMAIL` and `OWNER_EMAIL` will receive an email with a plain-text
summary and the full JSON report attached. In `server` mode a copy of the
report is also saved under `reports/`; in `direct_email` mode (see below)
the agent doesn't save a local copy unless you pass `--output`.

## Portable agent (USB / no server)

For scanning a machine that either doesn't have Python installed, or
can't reach your report server (e.g. an isolated network), package the
agent as a single standalone `.exe` and have it email the report
directly via SMTP — set `DELIVERY_MODE=direct_email` in `.env` for this.
The interactive **"Do you have authorization to scan this machine?"**
consent prompt still runs first, exactly as it does from source; nothing
about the packaged build skips or weakens it.

### 1. Build the .exe

From the `security-scanner` directory, with the venv from Setup step 2
active:

```powershell
pip install pyinstaller
pyinstaller --onefile --console --name security-scan-agent `
  --collect-all pydantic --collect-all pydantic_core `
  --collect-all email_validator --collect-all certifi `
  --clean --noconfirm `
  agent_entry.py
```

- `agent_entry.py` (project root) is the PyInstaller entry point — it
  exists because `agent/run.py` uses package-relative imports that only
  resolve when run as `python -m agent.run`, not when PyInstaller executes
  it directly.
- The `--collect-all` flags bundle a few packages (pydantic's compiled
  core, email-validator, certifi's CA bundle) that PyInstaller's static
  analysis doesn't always find on its own; without them the build can
  produce an exe that fails at runtime instead of at build time.
- **The .exe lands at `dist\security-scan-agent.exe`** (about 17 MB,
  single file). `build\` and `security-scan-agent.spec` are intermediate
  build artifacts — safe to ignore or delete after the build. All three
  are git-ignored; the .exe is a build output, not something to commit.

### 2. Prepare the USB drive

Copy two files onto the drive, in the same folder:
- `dist\security-scan-agent.exe`
- a `.env` file (copied from `.env.example`) with, at minimum:
  ```
  DELIVERY_MODE=direct_email
  OWNER_EMAIL=<the machine owner's address>
  ADMIN_EMAIL=<your address>
  SMTP_HOST=...
  SMTP_PORT=587
  SMTP_USE_TLS=true
  SMTP_USERNAME=...
  SMTP_PASSWORD=...
  ```

The agent looks for `.env` next to the .exe itself (not the current
working directory), so this works regardless of how the .exe is launched
on the target machine — double-click, a shortcut, or a shell that `cd`'d
somewhere else first.

⚠️ `.env` contains an SMTP password in plain text. Treat the USB drive
like any other credential — use an app password with minimal scope, and
don't leave the drive somewhere untrusted.

### 3. Run it on the target machine

With the owner present and their consent already obtained:

1. Plug in the USB drive and open it in File Explorer.
2. Double-click `security-scan-agent.exe`. A console window opens and asks:
   `Do you have authorization to scan this machine? [y/N]:` — type `y` and
   press Enter. (For a non-interactive run, e.g. from a script, open a
   terminal on the drive instead and run `.\security-scan-agent.exe --yes`.)
3. The scan runs (a few seconds), then the console prints where the
   report was emailed. No installation, no admin server, no Python
   required on the target machine.
4. Elevation note: as with running from source, launching as
   Administrator picks up more registry/task/connection detail; running
   without it still works, just with some entries silently skipped.

## Notes and limitations

- Persistence collectors (registry Run keys, scheduled tasks, startup
  folders) are Windows-specific and return empty results on other OSes;
  process/network/hash collection is cross-platform via `psutil`.
- File hashing automatically covers every executable referenced by a
  discovered persistence entry, plus any paths listed in
  `EXTRA_HASH_PATHS`. Set `HASH_PROCESS_EXECUTABLES=true` to also hash
  every running process's executable (slower).
- This is a point-in-time inventory/triage tool, not an intrusion
  detection system — it doesn't judge what it finds as malicious. Treat
  the emailed report as something to review, not an alert.
- The API key is a simple shared secret suitable for a trusted
  agent-to-server link; put the server behind HTTPS (e.g. a reverse
  proxy) before using it across an untrusted network.
- The packaged `.exe` is unsigned, so Windows SmartScreen or an antivirus
  product may flag or block it on first run (this is generic behavior
  toward unsigned executables, not specific to this tool). Code-signing
  it is out of scope here; if that's a blocker, run the agent from source
  via `python -m agent.run` instead.
