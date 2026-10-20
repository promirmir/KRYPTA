"""Adversarial tests for the isolated HORIZON/0 research scheme.

These tests are NOT security proofs and do not exercise system-disk encryption.
"""
from __future__ import annotations

import os
import pytest
from research.horizon_lab import (
    HorizonError, MAGIC, MAX_BLOCK_BYTES, RECORD, open_block, seal_block,
)


@pytest.mark.parametrize("size", [0, 1, 15, 16, 31, 4095, 4096, 4097, 65536])
def test_round_trip(size):
    key = os.urandom(32)
    data = os.urandom(size)
    record = seal_block(key, 12, 3, data, b"trusted-application-context")
    assert record.startswith(MAGIC)
    assert len(record) == RECORD.size + size + 32
    assert open_block(key, 12, 3, record, b"trusted-application-context") == data


def test_same_plaintext_yields_distinct_records():
    key = os.urandom(32)
    records = [seal_block(key, 1, 5, b"x" * 4096) for _ in range(12)]
    assert len(set(records)) == len(records)


@pytest.mark.parametrize("offset", [0, 3, 8, 12, 22, 26, 35, 51, 64, 75, 83, 84, 93, 110])
def test_bit_flips_rejected(offset):
    key = os.urandom(32)
    record = bytearray(seal_block(key, 123, 4, os.urandom(128)))
    record[offset] ^= 1
    with pytest.raises(HorizonError):
        open_block(key, 123, 4, bytes(record))


def test_wrong_master_key_rejected():
    record = seal_block(os.urandom(32), 4, 5, b"only-test-data")
    with pytest.raises(HorizonError):
        open_block(os.urandom(32), 4, 5, record)


def test_wrong_block_address_or_generation_rejected():
    key = os.urandom(32)
    record = seal_block(key, 4, 5, b"sample")
    for index, generation in [(3, 5), (4, 4), (4, 6), (5, 5)]:
        with pytest.raises(HorizonError):
            open_block(key, index, generation, record)


def test_wrong_external_context_rejected():
    key = os.urandom(32)
    record = seal_block(key, 4, 5, b"sample", aad=b"trusted-context")
    with pytest.raises(HorizonError):
        open_block(key, 4, 5, record, aad=b"untrusted-context")


def test_truncation_and_extra_trailing_data_rejected():
    key = os.urandom(32)
    record = seal_block(key, 4, 5, b"sample")
    for altered in [record[:-1], record[:RECORD.size - 1], record + b"x"]:
        with pytest.raises(HorizonError):
            open_block(key, 4, 5, altered)


@pytest.mark.parametrize("key", [b"", b"short", b"x" * 31, b"x" * 33])
def test_reject_incorrect_master_length(key):
    with pytest.raises(HorizonError):
        seal_block(key, 1, 1, b"data")


@pytest.mark.parametrize("invalid", [-1, 1 << 64, 0.5, True, "1"])
def test_reject_invalid_index_and_generation(invalid):
    with pytest.raises(HorizonError):
        seal_block(b"K" * 32, invalid, 1, b"test")
    with pytest.raises(HorizonError):
        seal_block(b"K" * 32, 1, invalid, b"test")


def test_reject_invalid_payload_size():
    with pytest.raises(HorizonError):
        seal_block(b"K" * 32, 1, 1, b"x" * (MAX_BLOCK_BYTES + 1))


def test_reject_invalid_aad_size():
    with pytest.raises(HorizonError):
        seal_block(b"K" * 32, 1, 1, b"x", aad=b"x" * 4097)


def test_research_module_has_no_disk_mount_or_bitlocker_dependency():
    import inspect
    from research import horizon_lab
    src = inspect.getsource(horizon_lab)
    assert "subprocess" not in src
    assert "os.system" not in src
    assert "BitLocker" not in src
    assert "cryptsetup" not in src


def test_rollback_requires_external_trusted_version_anchor():
    key = os.urandom(32)
    old = seal_block(key, 7, 1, b"old")
    new = seal_block(key, 7, 2, b"new")
    assert open_block(key, 7, 2, new) == b"new"
    with pytest.raises(HorizonError):
        open_block(key, 7, 2, old)
    # The old record authenticates if the attacker also convinces the caller
    # that generation 1 is expected. This test makes the limitation explicit.
    assert open_block(key, 7, 1, old) == b"old"
