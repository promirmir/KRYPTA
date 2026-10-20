"""KRYPTA-FS/0 disposable demonstration; no real disk/credentials affected.

Run: python -m research.fs_demo
"""
from __future__ import annotations

import hashlib
import json
import secrets
import tempfile
from pathlib import Path

from .fs_image import ResearchFileSystem
from .volume_image import ResearchVolume


def run_demo() -> dict:
    key = secrets.token_bytes(32)
    sample = b'KRYPTA research automatic encrypted file write' * 55
    with tempfile.TemporaryDirectory(prefix='krypta-fs-research-') as tmp:
        image = Path(tmp) / 'temporary.kvi'
        with ResearchVolume(image, key, create=True) as volume:
            fs = ResearchFileSystem.format(volume)
            fs.write_file('Przykład_你好.txt', sample)
            fs.write_file('Second-file.bin', secrets.token_bytes(4500))
            fs.rename_file('Second-file.bin', 'renamed.bin')
            receipt, sequence = fs.receipt, fs.sequence
        with ResearchVolume(image, key, expected_receipt=receipt, expected_sequence=sequence) as volume:
            fs = ResearchFileSystem(volume)
            if fs.read_file('Przykład_你好.txt') != sample:
                raise RuntimeError('KRYPTA file round-trip mismatch')
            if fs.list_files() != ['Przykład_你好.txt', 'renamed.bin']:
                raise RuntimeError('KRYPTA directory mismatch')
    return {
        'result': 'PASS',
        'format': 'KRYPTA-FS/0',
        'cipher_backing': 'KRYPTA-VIMG/0 experimental HORIZON',
        'file_sha256': hashlib.sha256(sample).hexdigest(),
        'temporary_image_deleted': True,
        'physical_disk_modified': False,
        'actual_disk_mount_supported': False,
        'production_encryption': False,
    }


def main() -> int:
    print(json.dumps(run_demo(), ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())