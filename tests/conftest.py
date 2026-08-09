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
