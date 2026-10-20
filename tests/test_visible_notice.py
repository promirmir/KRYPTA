from krypta.core import encrypt_file, file_info, decrypt_file, CryptoError
import pytest


def test_readable_notice_accurate_for_pin_only(tmp_path):
    plain = tmp_path / 'input.txt'
    plain.write_text('public format and private data', encoding='utf8')
    enc = tmp_path / 'test.kry'
    encrypt_file(plain, enc, '1')
    public = enc.read_bytes()[:1024]
    assert public.startswith(b'KRYPTA / AUTHENTICATED ENCRYPTED FILE\n')
    assert b'PIN/password only (offline guessing possible)' in public
    assert b'NOT INDEPENDENTLY AUDITED' in public
    assert b'NOT protect short PINs from offline guesses' in public
    assert file_info(enc)['verified'] is False
    assert b'public format and private data' not in enc.read_bytes()
    output = tmp_path / 'out.txt'
    decrypt_file(enc, output, '1')
    assert output.read_bytes() == plain.read_bytes()


def test_visible_notice_cannot_be_modified_undetected(tmp_path):
    plain = tmp_path / 'file'
    plain.write_bytes(b'hello')
    enc = tmp_path / 'encrypted'
    encrypt_file(plain, enc, 'test password')
    buf = enc.read_bytes().replace(b'NOT INDEPENDENTLY AUDITED',
                                  b'NOW INDEPENDENTLY AUDITED', 1)
    enc.write_bytes(buf)
    out = tmp_path / 'out'
    with pytest.raises(CryptoError):
        decrypt_file(enc, out, 'test password')
    assert not out.exists()


def test_unknown_payload_rejected(tmp_path):
    f = tmp_path / 'fake.kry'
    f.write_bytes(b'KRYPTA / totally secure, trust me\n' + b'0' * 100)
    with pytest.raises(CryptoError):
        file_info(f)