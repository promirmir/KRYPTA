"""Isolated Tk gate unit tests (no real display required)."""
import subprocess

import pytest

from tools import test_windows_gui_isolated as gate


def test_pytest_node_collection_requires_both_gui_modules():
    ids = gate.parse_collected_nodeids(
        "tests\\test_volume_lab_gui.py::test_one\n"
        "tests/test_desktop_languages.py::test_locales\n"
        "2 tests collected in 0.12s\n"
    )
    assert ids == [
        "tests/test_volume_lab_gui.py::test_one",
        "tests/test_desktop_languages.py::test_locales",
    ]
    with pytest.raises(RuntimeError, match="no collected"):
        gate.parse_collected_nodeids("tests/test_volume_lab_gui.py::test_one\n")
    with pytest.raises(RuntimeError, match="Duplicate"):
        gate.parse_collected_nodeids(
            "tests/test_volume_lab_gui.py::test_one\n"
            "tests/test_volume_lab_gui.py::test_one\n"
            "tests/test_desktop_languages.py::test_locales\n"
        )


def test_windows_gui_gate_reruns_all_cases_in_fresh_processes(monkeypatch):
    calls = []
    def run(args, **kwargs):
        calls.append((args, kwargs))
        if "--collect-only" in args:
            return subprocess.CompletedProcess(args, 0, (
                "tests/test_volume_lab_gui.py::test_one\n"
                "tests/test_desktop_languages.py::test_locales\n"
            ), "")
        return subprocess.CompletedProcess(args, 0)
    monkeypatch.setattr(gate.subprocess, "run", run)
    assert gate.run_gui_smoke(repeat=2, python_executable="dummy-python") == 4
    assert len(calls) == 5
    assert calls[0][0][1:4] == ["-m", "pytest", "--collect-only"]
    assert all(c[0][:3] == ["dummy-python", "-m", "pytest"]
               for c in calls)
    assert all(c[1].get("check") is False for c in calls)
    assert all(c[0][-1].startswith("tests/") for c in calls[1:])


def test_windows_gui_gate_does_not_suppress_or_retry_failing_test(monkeypatch):
    calls = []
    def run(args, **kwargs):
        calls.append(args)
        if "--collect-only" in args:
            return subprocess.CompletedProcess(args, 0, (
                "tests/test_volume_lab_gui.py::test_one\n"
                "tests/test_desktop_languages.py::test_locales\n"
            ), "")
        return subprocess.CompletedProcess(args, 1)
    monkeypatch.setattr(gate.subprocess, "run", run)
    with pytest.raises(RuntimeError, match="without retries"):
        gate.run_gui_smoke(repeat=3, python_executable="dummy-python")
    assert len(calls) == 2


def test_windows_gui_gate_fails_when_collection_fails(monkeypatch):
    def broken(args, **kwargs):
        assert "--collect-only" in args
        return subprocess.CompletedProcess(args, 2, "", "bad Tcl import")
    monkeypatch.setattr(gate.subprocess, "run", broken)
    with pytest.raises(RuntimeError, match="collection failed"):
        gate.run_gui_smoke(repeat=1, python_executable="dummy-python")


@pytest.mark.parametrize("repeat", [0, -1, 11, True, 2.5, "3"])
def test_windows_gui_gate_rejects_invalid_repeat_before_any_process(repeat):
    with pytest.raises(ValueError):
        gate.run_gui_smoke(repeat=repeat)
