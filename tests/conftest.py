"""
Sets required configuration as environment variables before any test
module imports agent.config / server.config / server.main, since the
server loads its config at import time. No .env file is used in CI.
"""
import os

os.environ.setdefault("API_KEY", "test-ci-key")
os.environ.setdefault("ADMIN_EMAIL", "admin@example.com")
os.environ.setdefault("OWNER_EMAIL", "owner@example.com")
os.environ.setdefault("SERVER_URL", "http://127.0.0.1:8000")

# Force these optional integrations off during tests, even if a developer's
# local .env has real keys in it (e.g. from manually trying the feature) -
# tests must never make real, rate-limited/billed calls to VirusTotal or the
# Anthropic API. python-dotenv only fills in unset variables, so setting
# these to "" here (which agent/config.py treats as unset) wins over .env.
os.environ["VIRUSTOTAL_API_KEY"] = ""
os.environ["ANTHROPIC_API_KEY"] = ""
