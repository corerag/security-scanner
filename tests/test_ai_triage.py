import json
from datetime import datetime, timezone

from agent import ai_triage
from common.schemas import (
    FileHashEntry,
    NetworkConnectionInfo,
    PersistenceReport,
    ProcessInfo,
    ScanReport,
)


class _FakeTextBlock:
    def __init__(self, text):
        self.type = "text"
        self.text = text


class _FakeResponse:
    def __init__(self, text="All clear.", stop_reason="end_turn"):
        self.content = [_FakeTextBlock(text)] if text is not None else []
        self.stop_reason = stop_reason


class _FakeMessages:
    def __init__(self, response=None, exc=None):
        self._response = response
        self._exc = exc
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        if self._exc:
            raise self._exc
        return self._response


class _FakeClient:
    def __init__(self, response=None, exc=None):
        self.messages = _FakeMessages(response, exc)


def _sample_report():
    return ScanReport(
        scan_id="55555555-5555-5555-5555-555555555555",
        hostname="triage-host",
        os_platform="Windows",
        os_version="10",
        agent_version="1.0.0",
        scan_started_at=datetime.now(timezone.utc),
        scan_completed_at=datetime.now(timezone.utc),
        owner_email="owner@example.com",
        processes=[ProcessInfo(pid=42, name="evil.exe", username="SYSTEM")],
        network_connections=[
            NetworkConnectionInfo(remote_address="1.2.3.4:443", status="ESTABLISHED", process_name="evil.exe")
        ],
        persistence=PersistenceReport(),
        file_hashes=[
            FileHashEntry(
                path="C:\\Users\\bob\\evil.exe",
                sha256="a" * 64,
                size_bytes=123,
                vt_malicious_count=5,
                vt_total_engines=70,
            )
        ],
    )


def test_skips_entirely_without_api_key():
    client = _FakeClient(response=_FakeResponse())
    result = ai_triage.generate_ai_summary(_sample_report(), api_key=None, client=client)
    assert result is None
    assert client.messages.calls == []


def test_returns_summary_text_on_success():
    client = _FakeClient(response=_FakeResponse(text="Nothing alarming; consider reviewing evil.exe."))
    result = ai_triage.generate_ai_summary(_sample_report(), api_key="sk-test", client=client)
    assert result == "Nothing alarming; consider reviewing evil.exe."
    assert len(client.messages.calls) == 1


def test_returns_none_on_refusal():
    client = _FakeClient(response=_FakeResponse(text=None, stop_reason="refusal"))
    result = ai_triage.generate_ai_summary(_sample_report(), api_key="sk-test", client=client)
    assert result is None


def test_returns_none_without_raising_on_api_failure():
    client = _FakeClient(exc=RuntimeError("connection reset"))
    result = ai_triage.generate_ai_summary(_sample_report(), api_key="sk-test", client=client)
    assert result is None


def test_returns_none_for_blank_response():
    client = _FakeClient(response=_FakeResponse(text="   "))
    result = ai_triage.generate_ai_summary(_sample_report(), api_key="sk-test", client=client)
    assert result is None


def test_prompt_frames_model_as_advisor_not_decider():
    client = _FakeClient(response=_FakeResponse())
    ai_triage.generate_ai_summary(_sample_report(), api_key="sk-test", client=client)

    call = client.messages.calls[0]
    system_prompt = call["system"].lower()
    assert "interpret and advise" in system_prompt
    assert "not to decide" in system_prompt
    assert "do not" in system_prompt and "malicious" in system_prompt


def test_only_sends_structured_findings_never_file_contents():
    client = _FakeClient(response=_FakeResponse())
    report = _sample_report()

    ai_triage.generate_ai_summary(report, api_key="sk-test", client=client)

    call = client.messages.calls[0]
    user_message = call["messages"][0]["content"]
    payload = json.loads(user_message.split("\n\n", 1)[1])

    assert payload["processes"] == [{"pid": 42, "name": "evil.exe", "username": "SYSTEM"}]
    assert payload["network_connections"][0]["remote_address"] == "1.2.3.4:443"
    assert payload["file_hashes"][0]["sha256"] == "a" * 64
    assert payload["file_hashes"][0]["vt_malicious_count"] == 5
    assert payload["file_hashes"][0]["vt_total_engines"] == 70
    # Only metadata - no field carries raw file bytes/contents.
    assert "content" not in payload["file_hashes"][0]
    assert "size_bytes" not in payload["file_hashes"][0]
