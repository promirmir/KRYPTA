"""No physical disks. Synthetic file image recovery, fail-closed tests."""
import os
import struct
import pytest

from research.volume_image import (
    ResearchVolume, VolumeImageError, BLOCK_BYTES, FRAME, HEADER_BYTES, MAX_BLOCKS,
)


def test_image_create_write_overwrite_reopen(tmp_path):
    p = tmp_path / 'test.kvi'
    key = os.urandom(32)
    with ResearchVolume(p, key, create=True) as v:
        assert v.sequence == 0
        assert v.read(5) == bytes(BLOCK_BYTES)
        assert v.write(5, b'A' * BLOCK_BYTES) == 1
        assert v.read(5) == b'A' * BLOCK_BYTES
        assert v.write(5, b'B' * BLOCK_BYTES) == 2
        assert v.write(20, os.urandom(BLOCK_BYTES)) == 3
        assert v.read(5) == b'B' * BLOCK_BYTES
    with ResearchVolume(p, key, expected_sequence=3) as v:
        assert v.sequence == 3
        assert v.read(5) == b'B' * BLOCK_BYTES
        assert v.read(7) == bytes(BLOCK_BYTES)


@pytest.mark.parametrize('i', [-1, 128, True, 1.3, '3'])
def test_invalid_addresses(tmp_path, i):
    with ResearchVolume(tmp_path/'a.kvi', os.urandom(32), create=True) as v:
        with pytest.raises(VolumeImageError): v.read(i)
        with pytest.raises(VolumeImageError): v.write(i, bytes(BLOCK_BYTES))


def test_wrong_key_does_not_modify_image(tmp_path):
    p = tmp_path/'a.kvi'
    key = os.urandom(32)
    with ResearchVolume(p, key, create=True) as v:
        v.write(1, os.urandom(BLOCK_BYTES))
    unchanged = p.read_bytes()
    with pytest.raises(VolumeImageError):
        ResearchVolume(p, os.urandom(32))
    assert p.read_bytes() == unchanged


def test_key_length_and_dangerous_target_rejected(tmp_path):
    with pytest.raises(VolumeImageError): ResearchVolume(tmp_path/'bad.kvi', b'short', create=True)
    with pytest.raises(VolumeImageError): ResearchVolume(tmp_path/'not-a-disk.img', os.urandom(32), create=True)


def test_no_overwrite_existing_image(tmp_path):
    p=tmp_path/'a.kvi'
    p.write_bytes(b'not a valid image')
    with pytest.raises(VolumeImageError): ResearchVolume(p,os.urandom(32),create=True)
    assert p.read_bytes()==b'not a valid image'


def test_no_silent_rollback_with_supplied_sequence(tmp_path):
    p=tmp_path/'a.kvi'
    key=os.urandom(32)
    with ResearchVolume(p,key,create=True) as v:
        v.write(2,b'Z'*BLOCK_BYTES)
        old=p.read_bytes()
        v.write(2,b'Y'*BLOCK_BYTES)
    p.write_bytes(old)
    with pytest.raises(VolumeImageError,match='rollback'):
        ResearchVolume(p,key,expected_sequence=2)
    # No trusted external sequence -> attacker can roll back a valid snapshot.
    with ResearchVolume(p,key) as v:
        assert v.sequence==1
        assert v.read(2)==b'Z'*BLOCK_BYTES


def test_torn_data_frame_before_commit_recovers_previous(tmp_path):
    p=tmp_path/'a.kvi'
    key=os.urandom(32)
    with ResearchVolume(p,key,create=True) as v:
        v.write(4,b'X'*BLOCK_BYTES)
        old_seq=v.sequence
    old_size=p.stat().st_size
    with open(p,'ab') as f:
        f.write(FRAME.pack(b'KVF0',b'D',5000))
        f.write(b'partial')
        f.flush();os.fsync(f.fileno())
    with ResearchVolume(p,key,expected_sequence=old_seq) as v:
        assert v.read(4)==b'X'*BLOCK_BYTES
    assert p.stat().st_size==old_size


def test_complete_uncommitted_data_is_ignored(tmp_path):
    p=tmp_path/'a.kvi'
    key=os.urandom(32)
    with ResearchVolume(p,key,create=True) as v:
        v.write(1,b'S'*BLOCK_BYTES)
        baseline=p.stat().st_size
    with open(p,'ab') as f:
        f.write(FRAME.pack(b'KVF0',b'D',100))
        f.write(b'Q'*100)
        f.flush();os.fsync(f.fileno())
    with ResearchVolume(p,key) as v:
        assert v.sequence==1
        assert v.read(1)==b'S'*BLOCK_BYTES
    assert p.stat().st_size==baseline


def test_tamper_last_committed_ciphertext_detected(tmp_path):
    p=tmp_path/'a.kvi'
    key=os.urandom(32)
    with ResearchVolume(p,key,create=True) as v:
        v.write(0,b'S'*BLOCK_BYTES)
        off=v.entries['0'][1]+FRAME.size+20
    with open(p,'r+b') as f:
        f.seek(off)
        c=f.read(1)
        f.seek(off)
        f.write(bytes([c[0]^1]))
    with pytest.raises(VolumeImageError): ResearchVolume(p,key)


def test_tamper_committed_manifest_mac_detected(tmp_path):
    p=tmp_path/'a.kvi'
    key=os.urandom(32)
    with ResearchVolume(p,key,create=True) as v:
        v.write(0,b'S'*BLOCK_BYTES)
    with open(p,'r+b') as f:
        f.seek(-1,2)
        last=f.read(1)
        f.seek(-1,2)
        f.write(bytes([last[0]^1]))
    with pytest.raises(VolumeImageError): ResearchVolume(p,key)


def test_header_tamper_detected(tmp_path):
    p=tmp_path/'a.kvi'
    key=os.urandom(32)
    with ResearchVolume(p,key,create=True): pass
    with open(p,'r+b') as f:
        f.seek(HEADER_BYTES-1)
        x=f.read(1)
        f.seek(HEADER_BYTES-1)
        f.write(bytes([x[0]^1]))
    with pytest.raises(VolumeImageError): ResearchVolume(p,key)


def test_unauthorized_midstream_write_rejected(tmp_path):
    p=tmp_path/'a.kvi'
    with ResearchVolume(p,os.urandom(32),create=True) as v:
        with pytest.raises(VolumeImageError):v.write(1,b'short')


def test_sparse_sectors_do_not_allocate_secret_data(tmp_path):
    p=tmp_path/'a.kvi'
    with ResearchVolume(p,os.urandom(32),create=True) as v:
        for i in range(MAX_BLOCKS):
            assert v.read(i)==bytes(BLOCK_BYTES)


def test_image_is_never_mountable_and_never_calls_external_disk_services():
    import inspect
    from research import volume_image
    source=inspect.getsource(volume_image)
    assert 'subprocess.run' not in source
    assert 'cryptsetup' not in source
    assert 'Enable-BitLocker' not in source


def test_interrupt_before_commit_keeps_previous_state(tmp_path, monkeypatch):
    p=tmp_path/'a.kvi'
    key=os.urandom(32)
    with ResearchVolume(p,key,create=True) as v:
        v.write(1,b'A'*BLOCK_BYTES)
        original=v.sequence
        real_frame=v._frame
        def simulate_cut(kind, payload):
            if kind == b'C':
                # End after full encrypted sector data is flushed, before commit.
                raise OSError('synthetic power failure before metadata commit')
            return real_frame(kind,payload)
        monkeypatch.setattr(v,'_frame',simulate_cut)
        with pytest.raises(OSError,match='power failure'):
            v.write(1,b'B'*BLOCK_BYTES)
    with ResearchVolume(p,key,expected_sequence=original) as reopened:
        assert reopened.read(1)==b'A'*BLOCK_BYTES
        assert reopened.write(1,b'C'*BLOCK_BYTES)==original+1
    with ResearchVolume(p,key,expected_sequence=original+1) as reopened:
        assert reopened.read(1)==b'C'*BLOCK_BYTES


def test_interrupted_commit_payload_keeps_previous_state(tmp_path):
    p=tmp_path/'a.kvi'
    key=os.urandom(32)
    with ResearchVolume(p,key,create=True) as v:
        v.write(8,b'E'*BLOCK_BYTES)
        oldsize=p.stat().st_size
    with open(p,'ab') as f:
        f.write(FRAME.pack(b'KVF0',b'C',300))
        f.write(b'only partial metadata')
        f.flush();os.fsync(f.fileno())
    with ResearchVolume(p,key,expected_sequence=1) as v:
        assert v.read(8)==b'E'*BLOCK_BYTES
    assert p.stat().st_size==oldsize


def test_reopened_image_is_locked_on_posix(tmp_path):
    import sys
    if sys.platform != 'linux': pytest.skip('POSIX advisory locking only')
    p=tmp_path/'a.kvi'
    key=os.urandom(32)
    with ResearchVolume(p,key,create=True) as a:
        with pytest.raises((OSError, VolumeImageError)):
            ResearchVolume(p,key)
    with ResearchVolume(p,key) as a:
        assert a.sequence == 0