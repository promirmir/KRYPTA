"""Synthetic-only PVIMG/1 tests. No disk devices, mountpoints, or actual secrets."""
from __future__ import annotations
import os
import random
import pytest
from research.paged_volume import (
    BLOCK_BYTES, MAX_BLOCKS, MAGIC, FRAME, HEADER_BYTES,
    PagedResearchVolume, PagedVolumeError,
)

def block(byte): return bytes([byte])*BLOCK_BYTES

def test_sparse_1gib_addressing_and_reopen(tmp_path):
    path=tmp_path/'sparse.kpv'; key=os.urandom(32)
    values={0:block(1),63:block(2),64:block(3),4095:block(4),4096:block(5),MAX_BLOCKS-1:block(6)}
    with PagedResearchVolume(path,key,create=True) as vol:
        assert vol.sequence == 0
        assert vol.read(MAX_BLOCKS-1)==bytes(BLOCK_BYTES)
        assert vol.write_many(values) == 1
        assert vol.read(65)==bytes(BLOCK_BYTES)
        assert vol.verify_all()['verified_sectors']==len(values)
        for idx,data in values.items(): assert vol.read(idx)==data
        receipt=vol.receipt
    assert path.stat().st_size < 100_000
    with PagedResearchVolume(path,key,expected_sequence=1,expected_receipt=receipt) as vol:
        for idx,data in values.items(): assert vol.read(idx)==data
        assert vol.verify_all()['verified_sectors']==len(values)

def test_randomized_model_and_multi_sector_commit(tmp_path):
    path=tmp_path/'random.kpv'; key=os.urandom(32)
    rng=random.Random(1761)
    expected={}
    with PagedResearchVolume(path,key,create=True) as vol:
        for seq in range(1,35):
            updates={rng.randrange(0,MAX_BLOCKS):rng.randbytes(BLOCK_BYTES) for _ in range(4)}
            assert vol.write_many(updates)==seq
            expected.update(updates)
            for idx,data in updates.items():assert vol.read(idx)==data
        receipt=vol.receipt
    with PagedResearchVolume(path,key,expected_sequence=34,expected_receipt=receipt) as vol:
        for idx,data in expected.items():assert vol.read(idx)==data
        assert vol.verify_all()['verified_sectors']==len(expected)

def test_reject_wrong_key_without_modifying_image(tmp_path):
    path=tmp_path/'key.kpv';key=os.urandom(32)
    with PagedResearchVolume(path,key,create=True) as vol:vol.write(100,block(12))
    before=path.read_bytes()
    with pytest.raises(PagedVolumeError,match='MAC'):
        PagedResearchVolume(path,os.urandom(32))
    assert path.read_bytes()==before

def test_external_rollback_uses_outside_receipt(tmp_path):
    path=tmp_path/'rollback.kpv';key=os.urandom(32)
    with PagedResearchVolume(path,key,create=True) as vol:
        vol.write(9,block(1)); old=path.read_bytes(); oldr=vol.receipt
        vol.write(9,block(2)); newest=vol.receipt
    path.write_bytes(old)
    with pytest.raises(PagedVolumeError,match='receipt mismatch'):
        PagedResearchVolume(path,key,expected_receipt=newest)
    with PagedResearchVolume(path,key,expected_receipt=oldr) as vol:assert vol.read(9)==block(1)

def test_fail_before_commit_does_not_publish_partial_batch(tmp_path,monkeypatch):
    path=tmp_path/'crash.kpv';key=os.urandom(32)
    with PagedResearchVolume(path,key,create=True) as vol:
        vol.write_many({1:block(8),MAX_BLOCKS-1:block(9)})
        receipt=vol.receipt
        original=vol._append
        def fault(kind,data):
            if kind==b'C':raise OSError('injected failure before COMMIT')
            return original(kind,data)
        monkeypatch.setattr(vol,'_append',fault)
        with pytest.raises(OSError,match='injected'):vol.write_many({1:block(6),4096:block(7)})
        with pytest.raises(PagedVolumeError,match='Uncertain'):vol.read(1)
    with PagedResearchVolume(path,key,expected_sequence=1,expected_receipt=receipt) as vol:
        assert vol.read(1)==block(8)
        assert vol.read(4096)==bytes(BLOCK_BYTES)
        assert vol.read(MAX_BLOCKS-1)==block(9)

def test_failed_ack_after_complete_commit_is_ambiguous(tmp_path,monkeypatch):
    path=tmp_path/'ack.kpv';key=os.urandom(32)
    with PagedResearchVolume(path,key,create=True) as vol:
        old=vol.receipt
        original=vol._append
        def fault(kind,data):
            result=original(kind,data)
            if kind==b'C':
                vol._flush()
                raise OSError('ack lost after committed frame')
            return result
        monkeypatch.setattr(vol,'_append',fault)
        with pytest.raises(OSError,match='ack lost'):vol.write(3,block(11))
        with pytest.raises(PagedVolumeError,match='Uncertain'):vol.write(3,block(12))
    with PagedResearchVolume(path,key,expected_sequence=1) as vol:assert vol.read(3)==block(11)
    with pytest.raises(PagedVolumeError,match='receipt mismatch'):
        PagedResearchVolume(path,key,expected_receipt=old)

def test_tampered_current_node_fails_closed_at_open(tmp_path):
    path=tmp_path/'node.kpv';key=os.urandom(32)
    with PagedResearchVolume(path,key,create=True) as vol:
        vol.write(5,block(1))
        off=vol.root[0]+FRAME.size+8
    with open(path,'r+b') as f:
        f.seek(off);v=f.read(1);f.seek(off);f.write(bytes([v[0]^1]))
    unchanged=path.read_bytes()
    with pytest.raises(PagedVolumeError,match='digest mismatch'):
        PagedResearchVolume(path,key)
    assert path.read_bytes()==unchanged

def test_tampered_current_sector_rejected_when_read(tmp_path):
    path=tmp_path/'sector.kpv';key=os.urandom(32)
    with PagedResearchVolume(path,key,create=True) as vol:
        vol.write(3,block(1))
        off=vol._entry(3)[1]+FRAME.size+22
    with open(path,'r+b') as f:
        f.seek(off);v=f.read(1);f.seek(off);f.write(bytes([v[0]^1]))
    with PagedResearchVolume(path,key) as vol:
        with pytest.raises(PagedVolumeError,match='tampering'):vol.read(3)

def test_torn_trailing_data_recovers_without_overwriting_previous_state(tmp_path):
    path=tmp_path/'tail.kpv';key=os.urandom(32)
    with PagedResearchVolume(path,key,create=True) as vol:
        vol.write(6,block(6));last=vol.receipt
    original=path.stat().st_size
    with open(path,'ab') as f:
        f.write(FRAME.pack(b'KPG1',b'D',2000)); f.write(b'not-complete')
    with PagedResearchVolume(path,key,expected_receipt=last) as vol:
        assert vol.read(6)==block(6)
    assert path.stat().st_size==original

def test_bad_inputs_cannot_mutate_image(tmp_path):
    path=tmp_path/'input.kpv';key=os.urandom(32)
    with PagedResearchVolume(path,key,create=True) as vol:
        before=path.read_bytes()
        for updates in [{}, {True:block(2)}, {-1:block(2)}, {MAX_BLOCKS:block(2)}, {5:b'short'}]:
            with pytest.raises(PagedVolumeError):vol.write_many(updates)
            assert path.read_bytes()==before
        vol.write(7,block(8))

def test_reject_devices_and_refuse_overwrite(tmp_path):
    key=os.urandom(32)
    with pytest.raises(PagedVolumeError):PagedResearchVolume(tmp_path/'bad.img',key,create=True)
    path=tmp_path/'existing.kpv';path.write_bytes(b'no-clobber')
    with pytest.raises(PagedVolumeError):PagedResearchVolume(path,key,create=True)
    assert path.read_bytes()==b'no-clobber'

def test_noncanonical_commit_even_with_valid_mac_is_rejected(tmp_path):
    import hmac
    from research.paged_volume import _json
    path=tmp_path/'signed-noncanonical.kpv'; key=os.urandom(32)
    with PagedResearchVolume(path,key,create=True) as vol:
        image_id=vol.id; mac_key=vol._mac_key
        bad=b'{"seq":0,"root":null,"prev":null}'
        assert bad != _json({'seq':0,'root':None,'prev':None})
        sig=hmac.digest(mac_key,MAGIC+image_id+bad,'sha256')
    path.write_bytes(MAGIC+image_id+FRAME.pack(b'KPG1',b'C',len(bad)+32)+bad+sig)
    snapshot=path.read_bytes()
    with pytest.raises(PagedVolumeError,match='Noncanonical'):
        PagedResearchVolume(path,key)
    assert path.read_bytes()==snapshot

def test_wrong_type_keys_fail_before_writing(tmp_path):
    path=tmp_path/'mixed.kpv';key=os.urandom(32)
    with PagedResearchVolume(path,key,create=True) as vol:
        snapshot=path.read_bytes()
        with pytest.raises(PagedVolumeError):vol.write_many({3:block(1),'4':block(2)})
        assert path.read_bytes()==snapshot

def test_output_contains_neither_test_plaintext_nor_other_volume_data(tmp_path):
    path=tmp_path/'private.kpv'; key=os.urandom(32)
    secret=b'KRYPTA_RESEARCH_ONLY_CLEAR_CANARY_'*30
    with PagedResearchVolume(path,key,create=True) as vol:
        vol.write_many({1:secret.ljust(BLOCK_BYTES,b'!'),MAX_BLOCKS-1:block(3)})
        assert vol.read(1).startswith(secret)
    assert secret not in path.read_bytes()

def test_posix_single_writer_file_lock(tmp_path):
    if os.name != 'posix':pytest.skip('POSIX advisory locks')
    path=tmp_path/'lock.kpv';key=os.urandom(32)
    with PagedResearchVolume(path,key,create=True):
        with pytest.raises((OSError,PagedVolumeError)):
            PagedResearchVolume(path,key)
