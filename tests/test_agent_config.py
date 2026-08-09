import pytest

from agent import config


def test_load_config_defaults_to_server_mode(monkeypatch):
    monkeypatch.setenv("OWNER_EMAIL", "owner@example.com")
    monkeypatch.setenv("API_KEY", "k")
    monkeypatch.delenv("DELIVERY_MODE", raising=False)

    cfg = config.load_config()

    assert cfg.delivery_mode == "server"
    assert cfg.api_key == "k"


def test_load_config_server_mode_requires_api_key(monkeypatch):
    monkeypatch.setenv("OWNER_EMAIL", "owner@example.com")
    monkeypatch.setenv("DELIVERY_MODE", "server")
    monkeypatch.delenv("API_KEY", raising=False)

    with pytest.raises(RuntimeError, match="API_KEY"):
        config.load_config()


def test_load_config_direct_email_requires_admin_email(monkeypatch):
    monkeypatch.setenv("OWNER_EMAIL", "owner@example.com")
    monkeypatch.setenv("DELIVERY_MODE", "direct_email")
    monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
    monkeypatch.delenv("ADMIN_EMAIL", raising=False)

    with pytest.raises(RuntimeError, match="ADMIN_EMAIL"):
        config.load_config()


def test_load_config_direct_email_requires_smtp_host(monkeypatch):
    monkeypatch.setenv("OWNER_EMAIL", "owner@example.com")
    monkeypatch.setenv("DELIVERY_MODE", "direct_email")
    monkeypatch.setenv("ADMIN_EMAIL", "admin@example.com")
    monkeypatch.delenv("SMTP_HOST", raising=False)

    with pytest.raises(RuntimeError, match="SMTP_HOST"):
        config.load_config()


def test_load_config_direct_email_succeeds_with_smtp_settings(monkeypatch):
    monkeypatch.setenv("OWNER_EMAIL", "owner@example.com")
    monkeypatch.setenv("DELIVERY_MODE", "direct_email")
    monkeypatch.setenv("ADMIN_EMAIL", "admin@example.com")
    monkeypatch.setenv("SMTP_HOST", "smtp.example.com")

    cfg = config.load_config()

    assert cfg.delivery_mode == "direct_email"
    assert cfg.admin_email == "admin@example.com"
    assert cfg.smtp_host == "smtp.example.com"


def test_load_config_rejects_invalid_delivery_mode(monkeypatch):
    monkeypatch.setenv("OWNER_EMAIL", "owner@example.com")
    monkeypatch.setenv("DELIVERY_MODE", "carrier_pigeon")

    with pytest.raises(RuntimeError, match="DELIVERY_MODE"):
        config.load_config()


def test_load_config_virustotal_api_key_defaults_to_none(monkeypatch):
    monkeypatch.setenv("OWNER_EMAIL", "owner@example.com")
    monkeypatch.setenv("API_KEY", "k")
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)

    cfg = config.load_config()

    assert cfg.virustotal_api_key is None


def test_load_config_reads_virustotal_api_key_when_set(monkeypatch):
    monkeypatch.setenv("OWNER_EMAIL", "owner@example.com")
    monkeypatch.setenv("API_KEY", "k")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-secret")

    cfg = config.load_config()

    assert cfg.virustotal_api_key == "vt-secret"
