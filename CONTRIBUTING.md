# Contributing

Thanks for your interest in improving this project. It's a small,
consent-based endpoint scanner (Python agent + FastAPI report server),
and contributions of any size are welcome — bug fixes, new collectors,
docs improvements, or platform support.

## Ground rules

- **This tool inspects live systems.** Only test it against machines you
  own or are explicitly authorized to scan. Don't submit changes that
  weaken the consent prompt in `agent/run.py` or that would make the
  agent run silently/without confirmation by default.
- Keep the agent/server split intact: the agent collects and reports,
  the server stores and emails. Avoid adding capabilities that let the
  server reach back and control the agent (this is a one-way reporting
  tool, not remote-management software).
- No telemetry, analytics, or network calls beyond `SERVER_URL` — the
  scope of what this tool talks to should stay obvious from `.env`.

## Getting set up

```powershell
git clone https://github.com/corerag/security-scanner.git
cd security-scanner
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt   # includes ruff, pytest, httpx on top of requirements.txt
copy .env.example .env
# fill in .env with test values - see README.md for a local SMTP debug
# server approach so you don't need real email credentials to test
```

See `README.md` for how to run the agent and server locally.

## Making a change

1. Fork the repo and create a branch off `main` (`git checkout -b fix/short-description`).
2. Keep changes focused — one logical change per pull request.
3. Match the existing module layout:
   - `common/schemas.py` — shared Pydantic models (the agent/server contract)
   - `common/email_report.py` — email building/sending, shared by the server
     and the agent's `direct_email` delivery mode; don't duplicate this logic
     in `server/email_service.py` or `agent/direct_email.py`, extend the shared module instead
   - `agent/collectors/` — one file per data source (processes, network, persistence, file hashes)
   - `server/` — FastAPI app, storage, email
4. If you add a new collector or field, update `common/schemas.py` first,
   then the collector, then `agent/reporter.py` (which wires collectors
   together), then `common/email_report.py`'s summary if the new data
   should appear in the emailed report.
5. Run `ruff check .` and `pytest -q` before submitting — CI runs both on
   every push/PR (`.github/workflows/ci.yml`) on Windows and Linux.
6. Also run a manual smoke test: start the server, run the agent with
   `--dry-run --output scan.json` and confirm the JSON looks right, then a
   real run against a local server (a local debug SMTP server — e.g.
   `pip install aiosmtpd && python -m aiosmtpd -n -l 127.0.0.1:1025` —
   avoids needing real email credentials). If your change touches
   `agent_entry.py`, `agent/direct_email.py`, or delivery-mode handling in
   `agent/run.py`, also rebuild the PyInstaller `.exe` (see README
   "Portable agent") and run it standalone to confirm it still works.
7. Update `README.md` / `.env.example` if you add new configuration.

## Pull requests

- Describe what changed and why in the PR description.
- Note any new environment variables or dependencies.
- Mention what platforms you tested on (persistence collectors are
  currently Windows-only and degrade to empty results elsewhere by
  design — cross-platform persistence support is a welcome contribution).

## Reporting bugs / requesting features

Please use the issue templates under `.github/ISSUE_TEMPLATE/` — they
ask for the context (OS, Python version, whether it's the agent or
server) needed to reproduce most issues quickly.

## Security issues

If you find a way this tool could be misused against a system without
consent, or a vulnerability in the report server (e.g. auth bypass,
injection), please open a private report rather than a public issue —
use GitHub's "Report a vulnerability" flow under the repo's Security tab.
