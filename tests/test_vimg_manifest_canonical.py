"""Strict authenticated VIMG commit parsing — only disposable regular files.

The test deliberately knows the ephemeral MAC key. An unauthenticated attacker
cannot produce these commits. This catches ambiguous/legacy encoder behavior
before future migration, parser changes or cross-language implementations.
"""
from __future__ import annotations

import hmac
import os

import pytest

from research.volume_image import (
    FRAME, HEADER_BYTES, MAGIC, ResearchVolume, VolumeImageError,
    _manifest_bytes,
)


def _signed_genesis(path, key: bytes, make_content) -> None:
    """Rebuild a test-only genesis frame with a fresh, valid commit HMAC."""
    with ResearchVolume(path, key, create=True) as image:
        image_id = image.id
        mac_key = image._mac_key
        canonical = _manifest_bytes(0, image_id, {})
    content = make_content(canonical, image_id)
    signed = content + hmac.digest(mac_key, MAGIC + image_id + content, "sha256")
    path.write_bytes(MAGIC + image_id + FRAME.pack(b"KVF0", b"C", len(signed)) + signed)


@pytest.mark.parametrize(
    "encoding",
    ["reordered", "whitespace", "duplicate_seq", "duplicate_entry"],
)
def test_valid_mac_does_not_override_noncanonical_commit_refusal(tmp_path, encoding):
    path = tmp_path / "signed-but-noncanonical.kvi"
    key = os.urandom(32)

    def alternate(canonical: bytes, image_id: bytes) -> bytes:
        assert canonical.startswith(b'{"entries":{},"id":"')
        image_hex = image_id.hex()
        if encoding == "reordered":
            return ('{"seq":0,"id":"' + image_hex + '","entries":{}}').encode()
        if encoding == "whitespace":
            return canonical + b" "
        if encoding == "duplicate_seq":
            return ('{"entries":{},"id":"' + image_hex +
                    '","seq":0,"seq":0}').encode()
        if encoding == "duplicate_entry":
            return ('{"entries":{"1":[],"1":[]},"id":"' + image_hex +
                    '","seq":0}').encode()
        raise AssertionError(encoding)

    _signed_genesis(path, key, alternate)
    before = path.read_bytes()
    with pytest.raises(VolumeImageError, match="Noncanonical"):
        ResearchVolume(path, key)
    # Failed verification must not repair, truncate or rewrite untrusted data.
    assert path.read_bytes() == before


def test_canonical_signed_genesis_still_opens_and_commits(tmp_path):
    path = tmp_path / "canonical.kvi"
    key = os.urandom(32)
    _signed_genesis(path, key, lambda canonical, _: canonical)
    with ResearchVolume(path, key, expected_sequence=0) as image:
        assert image.write(1, b"Y" * 4096) == 1
        receipt = image.commit_receipt
    with ResearchVolume(path, key, expected_sequence=1,
                        expected_receipt=receipt) as recovered:
        assert recovered.read(1) == b"Y" * 4096


def test_bad_signature_remains_rejected_before_json_validation(tmp_path):
    path = tmp_path / "unsigned.kvi"
    key = os.urandom(32)
    with ResearchVolume(path, key, create=True):
        pass
    raw = bytearray(path.read_bytes())
    assert raw[:len(MAGIC)] == MAGIC
    assert len(raw) > HEADER_BYTES + FRAME.size + 32
    # Corrupt an authenticated manifest byte and leave MAC untouched.
    raw[HEADER_BYTES + FRAME.size + 3] ^= 1
    path.write_bytes(raw)
    unchanged = path.read_bytes()
    with pytest.raises(VolumeImageError, match="MAC"):
        ResearchVolume(path, key)
    assert path.read_bytes() == unchanged
