from agent import virustotal
from common.schemas import FileHashEntry


class _FakeResponse:
    def __init__(self, status_code, payload=None, headers=None):
        self.status_code = status_code
        self._payload = payload or {}
        self.headers = headers or {}

    def json(self):
        return self._payload


class _FakeSession:
    """Returns queued responses in order, one per .get() call, and records
    every call made so tests can assert on request count/arguments."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.calls: list[dict] = []

    def get(self, url, headers=None, timeout=None):
        self.calls.append({"url": url, "headers": headers, "timeout": timeout})
        return self._responses.pop(0)


def _stats_response(malicious=0, harmless=60, undetected=5):
    return _FakeResponse(
        200,
        {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": malicious,
                        "suspicious": 0,
                        "undetected": undetected,
                        "harmless": harmless,
                        "timeout": 0,
                    }
                }
            }
        },
    )


def _sample_hashes(n=1):
    return [
        FileHashEntry(path=f"C:\\file{i}.exe", sha256="a" * 64, size_bytes=10)
        for i in range(n)
    ]


def test_skips_entirely_without_api_key():
    hashes = _sample_hashes(1)
    result = virustotal.enrich_with_virustotal(hashes, api_key=None)
    assert result is hashes


def test_skips_entries_without_a_hash(monkeypatch):
    monkeypatch.setattr(virustotal, "_sleep", lambda seconds: None)
    entry = FileHashEntry(path="C:\\missing.exe", exists=False, error="File not found")
    session = _FakeSession([])

    result = virustotal.enrich_with_virustotal([entry], api_key="k", session=session)

    assert result[0].vt_malicious_count is None
    assert session.calls == []


def test_records_malicious_count_from_last_analysis_stats(monkeypatch):
    monkeypatch.setattr(virustotal, "_sleep", lambda seconds: None)
    session = _FakeSession([_stats_response(malicious=3, harmless=60, undetected=2)])

    result = virustotal.enrich_with_virustotal(_sample_hashes(1), api_key="k", session=session)

    assert result[0].vt_malicious_count == 3
    assert result[0].vt_total_engines == 65
    assert result[0].vt_error is None
    assert session.calls[0]["headers"] == {"x-apikey": "k"}
    assert session.calls[0]["url"].endswith("a" * 64)


def test_never_sends_file_contents_only_the_hash(monkeypatch):
    """Regression guard: the request body/URL must never contain anything
    other than the hash itself - no file path, no file bytes."""
    monkeypatch.setattr(virustotal, "_sleep", lambda seconds: None)
    session = _FakeSession([_stats_response()])
    entry = FileHashEntry(path="C:\\secret-project\\confidential.exe", sha256="b" * 64, size_bytes=10)

    virustotal.enrich_with_virustotal([entry], api_key="k", session=session)

    call = session.calls[0]
    assert call["url"] == f"{virustotal.VT_API_BASE}/{'b' * 64}"
    assert "secret-project" not in call["url"]


def test_404_marks_hash_as_not_found(monkeypatch):
    monkeypatch.setattr(virustotal, "_sleep", lambda seconds: None)
    session = _FakeSession([_FakeResponse(404)])

    result = virustotal.enrich_with_virustotal(_sample_hashes(1), api_key="k", session=session)

    assert result[0].vt_malicious_count is None
    assert result[0].vt_total_engines is None
    assert "not found" in result[0].vt_error.lower()


def test_429_retries_after_backoff_then_succeeds(monkeypatch):
    sleeps = []
    monkeypatch.setattr(virustotal, "_sleep", lambda seconds: sleeps.append(seconds))
    session = _FakeSession(
        [
            _FakeResponse(429, headers={"Retry-After": "20"}),
            _stats_response(malicious=1),
        ]
    )

    result = virustotal.enrich_with_virustotal(_sample_hashes(1), api_key="k", session=session)

    assert result[0].vt_malicious_count == 1
    assert len(session.calls) == 2
    assert 20 in sleeps


def test_429_gives_up_after_max_retries(monkeypatch):
    monkeypatch.setattr(virustotal, "_sleep", lambda seconds: None)
    responses = [_FakeResponse(429) for _ in range(virustotal.MAX_RETRIES_ON_RATE_LIMIT + 1)]
    session = _FakeSession(responses)

    result = virustotal.enrich_with_virustotal(_sample_hashes(1), api_key="k", session=session)

    assert result[0].vt_malicious_count is None
    assert "rate limit" in result[0].vt_error.lower()
    assert len(session.calls) == virustotal.MAX_RETRIES_ON_RATE_LIMIT + 1


def test_throttles_between_successive_lookups(monkeypatch):
    """Two hashes in one run must be spaced apart by at least
    min_interval_seconds, matching VirusTotal's free-tier rate limit."""
    fake_now = [1000.0]
    monkeypatch.setattr(virustotal.time, "monotonic", lambda: fake_now[0])

    sleeps = []

    def fake_sleep(seconds):
        sleeps.append(seconds)
        fake_now[0] += seconds

    monkeypatch.setattr(virustotal, "_sleep", fake_sleep)

    session = _FakeSession([_stats_response(), _stats_response()])

    virustotal.enrich_with_virustotal(
        _sample_hashes(2), api_key="k", session=session, min_interval_seconds=15.0
    )

    assert len(session.calls) == 2
    # No sleep before the first request, ~15s sleep before the second.
    assert sleeps[0] == 15.0


def test_does_not_mutate_input_list(monkeypatch):
    monkeypatch.setattr(virustotal, "_sleep", lambda seconds: None)
    original = _sample_hashes(1)
    session = _FakeSession([_stats_response(malicious=5)])

    virustotal.enrich_with_virustotal(original, api_key="k", session=session)

    assert original[0].vt_malicious_count is None
