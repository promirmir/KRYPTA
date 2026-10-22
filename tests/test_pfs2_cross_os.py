"""Offline assertions for the real Windows/Linux cross-runner fixture producer."""
from __future__ import annotations

import json

import pytest

from research.paged_volume import PagedVolumeError
from tools.test_pfs2_cross_os import (
    create, update, verify, FILENAME, INITIAL, UPDATED,
)


def test_complete_cross_os_fixture_trip_through_copy(tmp_path):
    root = str(tmp_path)
    create(root)
    image = tmp_path / FILENAME
    prior = json.loads((tmp_path / INITIAL).read_text())
    assert prior["test_only"] is True
    original = image.read_bytes()
    with pytest.raises(FileExistsError):
        create(root)
    assert image.read_bytes() == original
    update(root)
    assert image.read_bytes() != original
    current = json.loads((tmp_path / UPDATED).read_text())
    assert current["sequence"] == prior["sequence"] + 2
    assert current["receipt"] != prior["receipt"]
    changed = image.read_bytes()
    verify(root)
    assert image.read_bytes() == changed
    with pytest.raises(PagedVolumeError, match="receipt mismatch"):
        update(root)
    assert image.read_bytes() == changed


def test_wrong_current_receipt_never_accepted(tmp_path):
    create(str(tmp_path))
    update(str(tmp_path))
    manifest = tmp_path / UPDATED
    doc = json.loads(manifest.read_text())
    doc["receipt"] = "0" * 64 if doc["receipt"] != "0" * 64 else "1" * 64
    manifest.write_text(json.dumps(doc), encoding="ascii")
    original = (tmp_path / FILENAME).read_bytes()
    with pytest.raises(PagedVolumeError, match="receipt mismatch"):
        verify(str(tmp_path))
    assert (tmp_path / FILENAME).read_bytes() == original


def test_tampered_encrypted_cross_os_image_rejected(tmp_path):
    create(str(tmp_path))
    update(str(tmp_path))
    image = tmp_path / FILENAME
    altered = bytearray(image.read_bytes())
    # Flip a byte inside an authenticated reachable final root commit MAC.
    altered[-1] ^= 1
    image.write_bytes(altered)
    snapshot = image.read_bytes()
    with pytest.raises(PagedVolumeError, match="MAC"):
        verify(str(tmp_path))
    assert image.read_bytes() == snapshot


def test_cli_acknowledgement_is_required(tmp_path):
    from tools.test_pfs2_cross_os import main
    with pytest.raises(SystemExit):
        main(["--phase", "create", "--root", str(tmp_path)])
    assert list(tmp_path.iterdir()) == []


def test_missing_or_alias_manifest_refused(tmp_path):
    create(str(tmp_path))
    before = (tmp_path / FILENAME).read_bytes()
    (tmp_path / UPDATED).symlink_to(tmp_path / INITIAL)
    with pytest.raises(ValueError, match="invalid synthetic test manifest"):
        verify(str(tmp_path))
    assert (tmp_path / FILENAME).read_bytes() == before
