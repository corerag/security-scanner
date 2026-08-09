# Consent-Based Security Scanner

[![License: MIT](https://img.shields.io/github/license/corerag/security-scanner)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/server-FastAPI-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

A small, two-part scanning tool for **machines you own or are explicitly
authorized to scan**:

1. **Agent** (`agent/`) — runs locally on the target machine. Collects
   running processes, active network connections, common persistence
   locations (registry `Run`/`RunOnce` keys, scheduled tasks, startup
   folders), and SHA-256 hashes of the executables it finds, then submits
   the result to the report server.
2. **Server** (`server/`) — a FastAPI service that receives reports,
   stores them as JSON, and emails a summary to **two** addresses: yours
   (the admin) and the scanned machine owner's.

⚠️ **Only run the agent against systems you own or have explicit written
authorization to scan.** It requires interactive confirmation (or an
explicit `--yes` flag) before every scan for exactly this reason.

## How it works

```
 [ agent/run.py ]  --collects-->  ProcessInfo, NetworkConnectionInfo,
        |                          PersistenceReport, FileHashEntry
        |  builds common.schemas.ScanReport
        |  POST /api/v1/reports  (X-API-Key header)
        v
 [ server/main.py, FastAPI ]
        |  validates report (pydantic)
        |  saves JSON to STORAGE_DIR   (server/storage.py)
        |  emails summary + JSON attachment to
        |    ADMIN_EMAIL and report.owner_email  (server/email_service.py)
        v
   two inboxes: yours, and the machine owner's
```

## Project layout

```
security-scanner/
├── .env.example        # copy to .env and fill in real values
├── requirements.txt
├── common/
│   └── schemas.py       # shared Pydantic models (agent <-> server contract)
├── agent/
│   ├── config.py         # reads agent-side settings from .env
│   ├── reporter.py        # orchestrates collectors into a ScanReport
│   ├── run.py              # CLI entry point (consent prompt, submit/dry-run)
│   └── collectors/
│       ├── processes.py     # running processes (psutil)
│       ├── network.py        # active network connections (psutil)
│       ├── persistence.py     # registry Run keys, scheduled tasks, startup folders
│       ├── file_hashes.py      # SHA-256 hashing of discovered/watched files
│       └── utils.py             # command-line -> executable path extraction
└── server/
    ├── config.py         # reads server-side settings from .env
    ├── storage.py          # saves reports as JSON
    ├── email_service.py     # builds and sends the summary email
    └── main.py                # FastAPI app / HTTP endpoints
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
- `API_KEY` — a random shared secret (generate with
  `python -c "import secrets; print(secrets.token_urlsafe(32))"`), used by
  both the agent and the server.
- `ADMIN_EMAIL` — your address.
- `OWNER_EMAIL` — the address of whoever owns the machine being scanned
  (can be the same as `ADMIN_EMAIL` if you're scanning your own machine).
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD` — your SMTP
  provider's settings.
- `SERVER_URL` — where the agent should send reports (defaults to
  `http://127.0.0.1:8000` for running both parts on the same machine).

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
summary and the full JSON report attached, and a copy of the report will
be saved under `reports/`.

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
