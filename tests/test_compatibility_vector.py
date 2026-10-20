"""Synthetic KRYPTA-FILE/2 vector checked across Windows/Linux and Python versions.

Not proof of security. Fixture password is PUBLIC; never treat it as a credential.
"""
import base64
import hashlib
import json
from pathlib import Path

import pytest

from krypta.core import CryptoError, decrypt_file, file_info


VECTOR = Path(__file__).parent / 'vectors' / 'v2_public_compat.json'


def test_public_golden_v2_file_decrypts_on_current_crypto_backend(tmp_path):
    obj = json.loads(VECTOR.read_text(encoding='utf-8'))
    ciphertext = base64.b64decode(obj['ciphertext_base64'], validate=True)
    assert hashlib.sha256(ciphertext).hexdigest() == obj['cipher_sha256']
    enc = tmp_path / 'vector.kry'
    enc.write_bytes(ciphertext)
    info = file_info(enc)
    assert info['version'] == 2
    assert info['verified'] is False
    out = tmp_path / 'verified.bin'
    decrypt_file(enc, out, obj['password'])
    assert hashlib.sha256(out.read_bytes()).hexdigest() == obj['plain_sha256']


def test_public_golden_v2_rejects_bad_secret(tmp_path):
    obj = json.loads(VECTOR.read_text(encoding='utf-8'))
    enc = tmp_path / 'v2.kry'
    enc.write_bytes(base64.b64decode(obj['ciphertext_base64'], validate=True))
    with pytest.raises(CryptoError):
        decrypt_file(enc, tmp_path / 'should_not_exist', '9999')
    assert not (tmp_path / 'should_not_exist').exists()