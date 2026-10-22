"""Strict Windows Tk smoke gate: one fresh Tcl interpreter per test case.

The existing GUI assertions remain unchanged. Collection and every test are
run by pytest itself. No retries, xfail, fake display, altered exit status or
suppressed Tcl initialization errors. Run on real Windows desktop CI.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import sys

GUI_TEST_FILES = (
    "tests/test_volume_lab_gui.py",
    "tests/test_desktop_languages.py",
)


def parse_collected_nodeids(output: str, files=GUI_TEST_FILES) -> list[str]:
    """Only accept exact pytest node IDs from each required GUI module."""
    normalized = output.replace(chr(92), "/")
    found: list[str] = []
    for line in normalized.splitlines():
        node = line.strip()
        if any(node.startswith(path + "::") for path in files):
            if node in found:
                raise RuntimeError("Duplicate GUI node ID from pytest collection")
            found.append(node)
    for path in files:
        if not any(node.startswith(path + "::") for node in found):
            raise RuntimeError("GUI smoke module had no collected tests: " + path)
    return found


def run_gui_smoke(*, repeat: int = 3,
                  python_executable: str | None = None) -> int:
    """Run complete GUI smoke files with independent process per node ID."""
    if type(repeat) is not int or not 1 <= repeat <= 10:
        raise ValueError("Repeat count must be from 1 through 10")
    python = python_executable or sys.executable
    root = Path(__file__).resolve().parent.parent
    print("KRYPTA GUI isolated gate",
          f"python={python!r}", f"platform={sys.platform}",
          f"TCL_LIBRARY={os.environ.get('TCL_LIBRARY')!r}",
          f"TK_LIBRARY={os.environ.get('TK_LIBRARY')!r}", flush=True)
    cmd = [python, "-m", "pytest", "--collect-only", "-q", *GUI_TEST_FILES]
    collect = subprocess.run(cmd, cwd=str(root), capture_output=True,
                             text=True, timeout=90, check=False)
    if collect.returncode != 0:
        print(collect.stdout, collect.stderr, file=sys.stderr, flush=True)
        raise RuntimeError("Tk GUI test collection failed")
    nodes = parse_collected_nodeids(collect.stdout)
    print("Collected", len(nodes), "native GUI tests", flush=True)
    for cycle in range(1, repeat + 1):
        for node in nodes:
            print(f"GUI TEST {cycle}/{repeat}: {node}", flush=True)
            run = subprocess.run(
                [python, "-m", "pytest", "-q", "-rs", node],
                cwd=str(root), timeout=150, check=False,
            )
            if run.returncode != 0:
                raise RuntimeError(
                    f"GUI smoke failed without retries: {node} "
                    f"(cycle {cycle}, code {run.returncode})"
                )
    return len(nodes) * repeat


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repeat", type=int, default=3)
    args = parser.parse_args(argv)
    run_gui_smoke(repeat=args.repeat)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
