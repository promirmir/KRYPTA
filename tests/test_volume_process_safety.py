"""KRYPTA-VIMG/0 process exclusion and fail-closed recovery checks.

Test-only disposable regular image files. No real disks or user data.
"""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys

import pytest

from research.volume_image import (
    BLOCK_BYTES, FRAME, ResearchVolume, VolumeImageError,
)


def _append_incomplete_frame(path: Path) -> None:
    with path.open("ab") as out:
        out.write(FRAME.pack(b"KVF0", b"D", 700))
        out.write(b"incomplete data frame")
        out.flush()
        os.fsync(out.fileno())


def test_rejected_external_receipt_never_modifies_uncommitted_tail(tmp_path):
    image = tmp_path / "trust.kvi"
    key = os.urandom(32)
    with ResearchVolume(image, key, create=True) as v:
        v.write(4, b"A" * BLOCK_BYTES)
        expected = v.commit_receipt
    _append_incomplete_frame(image)
    before = image.read_bytes()
    with pytest.raises(VolumeImageError, match="receipt mismatch"):
        ResearchVolume(image, key, expected_receipt="0" * 64)
    assert image.read_bytes() == before
    # With valid external evidence the safe partial append is cleaned up.
    with ResearchVolume(image, key, expected_receipt=expected) as v:
        assert v.sequence == 1
        assert v.read(4) == b"A" * BLOCK_BYTES
    assert len(image.read_bytes()) < len(before)


def test_rejected_external_sequence_never_modifies_uncommitted_tail(tmp_path):
    image = tmp_path / "sequence.kvi"
    key = os.urandom(32)
    with ResearchVolume(image, key, create=True) as v:
        v.write(3, b"B" * BLOCK_BYTES)
    _append_incomplete_frame(image)
    before = image.read_bytes()
    with pytest.raises(VolumeImageError, match="sequence mismatch"):
        ResearchVolume(image, key, expected_sequence=5)
    assert image.read_bytes() == before
    with ResearchVolume(image, key, expected_sequence=1) as v:
        assert v.read(3) == b"B" * BLOCK_BYTES


def test_wrong_key_never_modifies_uncommitted_tail(tmp_path):
    image = tmp_path / "key.kvi"
    key = os.urandom(32)
    with ResearchVolume(image, key, create=True) as v:
        v.write(1, b"K" * BLOCK_BYTES)
    _append_incomplete_frame(image)
    before = image.read_bytes()
    with pytest.raises(VolumeImageError):
        ResearchVolume(image, os.urandom(32))
    assert image.read_bytes() == before


_SUBPROCESS_CODE = r"""
from pathlib import Path
import sys
from research.volume_image import ResearchVolume, VolumeImageError
try:
    with ResearchVolume(Path(sys.argv[1]), bytes.fromhex(sys.argv[2])) as image:
        assert image.sequence == 0
        print('OPENED', flush=True)
except (OSError, VolumeImageError):
    print('LOCKED', flush=True)
"""


def test_single_writer_lock_across_processes_on_windows_and_linux(tmp_path):
    image = tmp_path / "lock.kvi"
    key = os.urandom(32)
    repo_root = Path(__file__).resolve().parents[1]
    env = dict(os.environ)
    env["PYTHONPATH"] = str(repo_root)
    def child() -> str:
        run = subprocess.run(
            [sys.executable, "-c", _SUBPROCESS_CODE, str(image), key.hex()],
            env=env, capture_output=True, text=True, timeout=15, check=True,
        )
        return run.stdout.strip()
    with ResearchVolume(image, key, create=True) as v:
        assert child() == "LOCKED"
        assert v.sequence == 0
        assert v.read(0) == bytes(BLOCK_BYTES)
    assert child() == "OPENED"


def test_rejected_image_opens_release_cross_process_lock(tmp_path):
    image = tmp_path / "badkey.kvi"
    key = os.urandom(32)
    with ResearchVolume(image, key, create=True):
        pass
    with pytest.raises(VolumeImageError):
        ResearchVolume(image, os.urandom(32))
    with ResearchVolume(image, key) as v:
        assert v.sequence == 0


def test_no_hardware_device_support():
    # The research image intentionally has no block device handling.
    import inspect
    from research import volume_image
    text = inspect.getsource(volume_image)
    assert "Enable-BitLocker" not in text
    assert "cryptsetup" not in text
    assert "subprocess.run" not in text
