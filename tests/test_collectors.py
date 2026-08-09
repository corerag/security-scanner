import os

from agent.collectors.file_hashes import hash_paths
from agent.collectors.network import collect_network_connections
from agent.collectors.persistence import collect_persistence
from agent.collectors.processes import collect_processes
from agent.collectors.utils import extract_executable_path


def test_extract_executable_path_quoted():
    assert (
        extract_executable_path('"C:\\Program Files\\App\\app.exe" --flag')
        == "C:\\Program Files\\App\\app.exe"
    )


def test_extract_executable_path_unquoted_with_args():
    assert extract_executable_path(r"C:\Windows\System32\rundll32.exe some.dll,Entry") == (
        r"C:\Windows\System32\rundll32.exe"
    )


def test_extract_executable_path_handles_empty():
    assert extract_executable_path(None) is None
    assert extract_executable_path("") is None


def test_hash_paths_reports_missing_file_without_raising():
    results = hash_paths(["Z:\\definitely\\not\\a\\real\\path.exe"])
    assert len(results) == 1
    assert results[0].exists is False
    assert results[0].sha256 is None


def test_hash_paths_hashes_real_file(tmp_path):
    sample = tmp_path / "sample.txt"
    sample.write_bytes(b"hello world")

    results = hash_paths([str(sample)])

    assert len(results) == 1
    assert results[0].exists is True
    assert results[0].sha256 is not None
    assert results[0].size_bytes == len(b"hello world")


def test_collect_processes_returns_current_process():
    processes = collect_processes()
    pids = {p.pid for p in processes}
    assert os.getpid() in pids


def test_collect_network_connections_does_not_raise():
    # Contents vary a lot across CI runners; just verify the collector
    # runs cleanly and returns a list.
    connections = collect_network_connections()
    assert isinstance(connections, list)


def test_collect_persistence_does_not_raise_on_any_platform():
    # Persistence checks are Windows-specific and must degrade to empty
    # results (not raise) on other platforms.
    report = collect_persistence()
    assert isinstance(report.registry_run_keys, list)
    assert isinstance(report.scheduled_tasks, list)
    assert isinstance(report.startup_items, list)
