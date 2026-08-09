---
name: Bug report
about: Something in the agent or server isn't working as expected
title: "[Bug] "
labels: bug
assignees: ''
---

**Component**
- [ ] Agent (`agent/`)
- [ ] Server (`server/`)
- [ ] Shared schemas (`common/`)
- [ ] Docs / setup

**Describe the bug**
A clear, concise description of what's wrong.

**To reproduce**
Steps to reproduce the behavior, e.g.:
1. Set these `.env` values (redact secrets): ...
2. Run `python -m agent.run ...` or `uvicorn server.main:app ...`
3. See error

**Expected behavior**
What you expected to happen instead.

**Logs / output**
```
paste relevant terminal output, stack trace, or server log lines here
```

**Environment**
- OS: [e.g. Windows 11, Ubuntu 22.04]
- Python version: [`python --version`]
- Are you running the agent, the server, or both, and on the same machine?

**Additional context**
Anything else that might be relevant (e.g. running elevated/non-elevated,
custom `EXTRA_HASH_PATHS`, network restrictions, SMTP provider used).
