"""KRYPTA file vault research prototype, v2 experimental file format.

Authenticated encryption for regular files. NOT disk, boot, Android or hardware-bound encryption.
Never rely on this unaudited prototype for irreplaceable data.
"""
from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import os
import secrets
import stat
import struct
import tempfile
import unicodedata
from pathlib import Path
from typing import BinaryIO

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

MAGIC_V1 = b"KRYPTA01\x00"  # read-only backwards compatibility for alpha v0.2
MAGIC = b"KRYPTA02\x00"  # v2 writes only
NOTICE_END = b"END KRYPTA NOTICE\n"


def _notice(keyfile_required: bool) -> bytes:
    """Visible notice. Metadata is NOT independently authentic until decryption."""
    factor = ("PIN/password AND external keyfile" if keyfile_required
              else "PIN/password only (offline guessing possible)")
    return ("KRYPTA / AUTHENTICATED ENCRYPTED FILE\n"
            "Format: KRYPTA-FILE/2\n"
            "Cipher: AES-256-GCM authenticated encryption\n"
            "Key material: random 256-bit data encryption key\n"
            "Key derivation: Argon2id / HKDF-SHA-256\n"
            f"Unlock factors: {factor}\n"
            "Security status: RESEARCH ALPHA / NOT INDEPENDENTLY AUDITED\n"
            "Security claim: strong encryption does NOT protect short PINs from offline guesses\n"
            "Public header: UNVERIFIED until successful decryption\n"
            "END KRYPTA NOTICE\n").encode("ascii")
CHUNK_SIZE = 1024 * 1024
HEADER_MAX = 8192
KDF_MEM_KIB = 65536   # 64 MiB RFC 9106 second recommended profile
KDF_TIME = 3
KDF_PARALLELISM = 4
MAX_KEYFILE_BYTES = 1 << 20

class CryptoError(Exception):
    """Invalid ciphertext, missing material, or wrong password."""


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode('ascii')


def _unb64(value: str, length: int) -> bytes:
    if not isinstance(value, str):
        raise CryptoError('Nieprawidłowy nagłówek')
    try:
        result = base64.b64decode(value, validate=True)
    except Exception as exc:
        raise CryptoError('Nieprawidłowy nagłówek') from exc
    if len(result) != length:
        raise CryptoError('Nieprawidłowy nagłówek')
    return result


def _json(data: dict) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


@contextlib.contextmanager
def _open_checked_file(path: Path):
    """Open a regular input file by descriptor, rejecting POSIX symlink races.

    On POSIX, O_NOFOLLOW prevents replacing a checked file with a symlink
    between path inspection and open. O_NONBLOCK avoids waiting for a FIFO
    substituted by an attacker; fstat then rejects non-regular descriptors.
    Windows reparse points/hostile directories need separate native review.
    """
    p = Path(path)
    if p.is_symlink():
        raise CryptoError('Dowiązania symboliczne nie są akceptowane')
    flags = (os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) |
             getattr(os, 'O_CLOEXEC', 0) | getattr(os, 'O_NONBLOCK', 0) |
             getattr(os, 'O_BINARY', 0))
    try:
        fd = os.open(p, flags)
    except OSError as exc:
        raise CryptoError('Nie można bezpiecznie otworzyć pliku wejściowego') from exc
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise CryptoError('Plik wejściowy musi być zwykłym plikiem')
        with os.fdopen(fd, 'rb') as handle:
            fd = -1  # fdopen takes ownership
            yield handle
    finally:
        if fd >= 0:
            os.close(fd)


def _keyfile_digest(path: Path | None) -> bytes | None:
    if path is None:
        return None
    with _open_checked_file(Path(path)) as handle:
        length = os.fstat(handle.fileno()).st_size
        if length < 32 or length > MAX_KEYFILE_BYTES:
            raise CryptoError('Plik klucza musi być zwykłym plikiem (32 B - 1 MiB)')
        digest = hashlib.sha256()
        seen = 0
        while block := handle.read(65536):
            seen += len(block)
            if seen > MAX_KEYFILE_BYTES:
                raise CryptoError('Plik klucza przekracza limit 1 MiB')
            digest.update(block)
        if seen != length:
            raise CryptoError('Plik klucza zmienił rozmiar podczas odczytu')
        return digest.digest()


def _derive_wrap_key(password: str, salt: bytes, keyfile_digest: bytes | None, version: int = 2) -> bytes:
    if not isinstance(password, str) or len(password) == 0:
        raise CryptoError('Puste hasło nie jest obsługiwane; PIN jednocyfrowy jest dozwolony')
    norm = unicodedata.normalize('NFC', password)
    pwd = norm.encode('utf-8')
    if len(pwd) > 4096:
        raise CryptoError('Hasło za długie dla prototypu')
    derived = hash_secret_raw(
        secret=pwd, salt=salt, time_cost=KDF_TIME, memory_cost=KDF_MEM_KIB,
        parallelism=KDF_PARALLELISM, hash_len=32, type=Type.ID,
    )
    component = b'\x01' + keyfile_digest if keyfile_digest is not None else b'\x00'
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
                info=b'KRYPTA-v2-KEK' if version == 2 else b'KRYPTA-v1-KEK').derive(derived + component)


def generate_keyfile(path: str | Path) -> None:
    p = Path(path)
    # O_EXCL prevents overwrite; mode 0o600 avoids a permissions window on
    # POSIX (chmod after creation would be too late). Windows ACL security
    # is platform-specific and requires independent validation.
    flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL |
             getattr(os, 'O_CLOEXEC', 0) | getattr(os, 'O_BINARY', 0))
    fd = os.open(p, flags, 0o600)
    created = os.fstat(fd)
    try:
        with os.fdopen(fd, 'wb') as output:
            fd = -1
            output.write(secrets.token_bytes(32))
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        # A failed write or fsync must not leave a partial keyfile that might
        # subsequently be mistaken for working recovery material. Only remove
        # the exact file created by this operation, never a replaced path.
        try:
            current = os.stat(p, follow_symlinks=False)
            if (current.st_dev, current.st_ino) == (created.st_dev, created.st_ino):
                os.unlink(p)
        except OSError:
            pass
        raise
    finally:
        if fd >= 0:
            os.close(fd)


def _read_exact(f: BinaryIO, n: int) -> bytes:
    if n < 0 or n > CHUNK_SIZE + 1024:
        raise CryptoError('Nieprawidłowa długość danych')
    data = f.read(n)
    if len(data) != n:
        raise CryptoError('Ucięty plik')
    return data


def _read_header(f: BinaryIO) -> tuple[dict, bytes, bytes, bytes]:
    """Return (metadata, canonical JSON bytes, payload AAD hash, public notice)."""
    first = _read_exact(f, len(MAGIC_V1))
    if first == MAGIC_V1:
        notice = b""
        version = 1
    else:
        f.seek(0)
        parts = []
        count = 0
        for _ in range(16):
            line = f.readline(256)
            count += len(line)
            if not line or not line.endswith(b"\n") or count > 1024:
                raise CryptoError("Nieprawidłowa publiczna informacja o zabezpieczeniach")
            parts.append(line)
            if line == NOTICE_END:
                break
        else:
            raise CryptoError("Brak końca publicznego nagłówka")
        notice = b"".join(parts)
        if _read_exact(f, len(MAGIC)) != MAGIC:
            raise CryptoError("Nieprawidłowy format KRYPTA")
        version = 2
    size = struct.unpack('>I', _read_exact(f, 4))[0]
    if not 64 <= size <= HEADER_MAX:
        raise CryptoError('Nieprawidłowa długość nagłówka')
    raw = _read_exact(f, size)
    try:
        obj = json.loads(raw)
    except Exception as exc:
        raise CryptoError('Nieprawidłowy nagłówek JSON') from exc
    if not isinstance(obj, dict) or _json(obj) != raw:
        raise CryptoError('Nagłówek niekanoniczny')
    required = {'version', 'algorithm', 'chunk_size', 'kdf', 'salt', 'keyfile_required',
                'stream_nonce_prefix', 'wrap_nonce', 'wrapped_dek'}
    if version == 2:
        required |= {'format_id', 'assurance'}
    if set(obj) != required:
        raise CryptoError('Nieobsługiwany schemat nagłówka')
    if obj['version'] != version or obj['algorithm'] != 'AES-256-GCM-stream-v1' or obj['chunk_size'] != CHUNK_SIZE:
        raise CryptoError('Nieobsługiwana wersja formatu')
    if version == 2 and (obj['format_id'] != 'KRYPTA-FILE/2' or
                         obj['assurance'] != 'experimental_unaudited'):
        raise CryptoError('Nieobsługiwany format lub oświadczenie')
    if obj['kdf'] != {'name': 'Argon2id', 'memory_kib': KDF_MEM_KIB, 'time': KDF_TIME,
                      'parallelism': KDF_PARALLELISM}:
        raise CryptoError('Nieobsługiwane parametry KDF')
    if type(obj['keyfile_required']) is not bool:
        raise CryptoError('Nieprawidłowa flaga pliku klucza')
    _unb64(obj['salt'], 16)
    _unb64(obj['stream_nonce_prefix'], 4)
    _unb64(obj['wrap_nonce'], 12)
    _unb64(obj['wrapped_dek'], 48)
    if version == 2 and notice != _notice(obj['keyfile_required']):
        raise CryptoError('Publiczny nagłówek jest zmieniony lub podrobiony')
    return obj, raw, hashlib.sha256(notice + raw).digest(), notice


def file_info(path: str | Path) -> dict:
    with Path(path).open('rb') as f:
        header, _, _, notice = _read_header(f)
    return {
        **{k: header[k] for k in ('version', 'algorithm', 'chunk_size', 'kdf', 'keyfile_required')},
        'public_notice': notice.decode('ascii') if notice else 'LEGACY KRYPTA-FILE/1 (alpha)',
        'verified': False, 'verification': 'Nagłówek jest publiczny; niepotwierdzony bez odszyfrowania',
    }


def _prepare_paths(source: str | Path, output: str | Path) -> tuple[Path, Path]:
    source, output = Path(source), Path(output)
    if not source.is_file() or source.is_symlink():
        raise ValueError('Źródło musi być istniejącym zwykłym plikiem, bez dowiązań')
    if output.exists() or output.is_symlink():
        raise FileExistsError(f'Plik wynikowy już istnieje: {output}')
    if not output.parent.is_dir():
        raise ValueError('Folder docelowy nie istnieje')
    return source, output


def _atomic_write(output: Path, write_callback) -> None:
    # In-progress decrypted plaintext can be written to disk while decrypting.
    # For sensitive data use an encrypted destination volume.
    fd, temp_name = tempfile.mkstemp(prefix='.krypta-', suffix='.tmp', dir=output.parent)
    temp = Path(temp_name)
    try:
        try:
            os.chmod(temp, 0o600)
        except OSError:
            pass
        with os.fdopen(fd, 'wb') as out:
            write_callback(out)
            out.flush()
            os.fsync(out.fileno())
        if output.exists() or output.is_symlink():
            raise FileExistsError(f'Plik wynikowy już istnieje: {output}')
        # Atomic no-clobber publish on filesystems supporting hard links (NTFS/ext4).
        # Do not fall back to os.replace: another process might create output in a race.
        os.link(temp, output)
        temp.unlink()
    finally:
        if temp.exists():
            temp.unlink()


def _encrypt_reader(reader_factory, output: Path, password: str,
                    keyfile: str | Path | None = None) -> None:
    """Reuse the verified KRYPTA-FILE/2 stream for a context-managed input.

    Caller must validate input and destination BEFORE invoking this internal
    helper. Reader exits (including device revalidation) before publication.
    """
    key_digest = _keyfile_digest(Path(keyfile) if keyfile is not None else None)
    dek = secrets.token_bytes(32)
    salt = secrets.token_bytes(16)
    wrap_nonce = secrets.token_bytes(12)
    nonce_prefix = secrets.token_bytes(4)
    meta = {
        'version': 2, 'format_id': 'KRYPTA-FILE/2',
        'assurance': 'experimental_unaudited',
        'algorithm': 'AES-256-GCM-stream-v1', 'chunk_size': CHUNK_SIZE,
        'kdf': {'name': 'Argon2id', 'memory_kib': KDF_MEM_KIB,
                'time': KDF_TIME, 'parallelism': KDF_PARALLELISM},
        'salt': _b64(salt), 'keyfile_required': key_digest is not None,
        'stream_nonce_prefix': _b64(nonce_prefix), 'wrap_nonce': _b64(wrap_nonce),
    }
    wrap_key = _derive_wrap_key(password, salt, key_digest)
    notice = _notice(key_digest is not None)
    wrapped = AESGCM(wrap_key).encrypt(wrap_nonce, dek, _json(meta) + notice)
    header = _json({**meta, 'wrapped_dek': _b64(wrapped)})
    header_hash = hashlib.sha256(notice + header).digest()
    data_aead = AESGCM(dek)

    def write(out: BinaryIO) -> None:
        out.write(notice)
        out.write(MAGIC)
        out.write(struct.pack('>I', len(header)))
        out.write(header)
        with reader_factory() as inp:
            index = 0
            while chunk := inp.read(CHUNK_SIZE):
                if index >= 2**64 - 1:
                    raise CryptoError('Przekroczono maksymalną liczbę segmentów')
                nonce = nonce_prefix + index.to_bytes(8, 'big')
                ciphertext = data_aead.encrypt(nonce, chunk, header_hash + b'CHUNK' + index.to_bytes(8, 'big'))
                out.write(struct.pack('>I', len(ciphertext)))
                out.write(ciphertext)
                index += 1
            nonce = nonce_prefix + index.to_bytes(8, 'big')
            final_tag = data_aead.encrypt(nonce, b'', header_hash + b'FINAL' + index.to_bytes(8, 'big'))
            out.write(struct.pack('>I', 0))
            out.write(final_tag)
    _atomic_write(output, write)



def encrypt_file(source: str | Path, output: str | Path, password: str,
                 keyfile: str | Path | None = None) -> None:
    source, output = _prepare_paths(source, output)
    _encrypt_reader(lambda: _open_checked_file(source), output, password, keyfile)

def _decrypt_stream(inp: BinaryIO, data_aead: AESGCM, nonce_prefix: bytes,
                    header_hash: bytes, output: BinaryIO | None = None) -> None:
    """Authenticate the full payload, optionally writing verified chunks.

    With ``output=None``, no decrypted bytes are written to disk. A first
    verification pass avoids creating temporary plaintext for ordinary
    corrupted, truncated or appended files. A second authenticated pass
    is still required because the input may change between passes.
    """
    index = 0
    while True:
        if index >= 2**64 - 1:
            raise CryptoError('Zbyt wiele segmentów')
        size = struct.unpack('>I', _read_exact(inp, 4))[0]
        nonce = nonce_prefix + index.to_bytes(8, 'big')
        if size == 0:
            tag = _read_exact(inp, 16)
            try:
                final = data_aead.decrypt(nonce, tag, header_hash + b'FINAL' + index.to_bytes(8, 'big'))
                if final != b'':
                    raise CryptoError('Nieprawidłowe zakończenie')
            except InvalidTag as exc:
                raise CryptoError('Ucięcie lub zmiana szyfrogramu') from exc
            if inp.read(1):
                raise CryptoError('Niedozwolone dane na końcu pliku')
            return
        if not 17 <= size <= CHUNK_SIZE + 16:
            raise CryptoError('Nieprawidłowa długość segmentu')
        segment = _read_exact(inp, size)
        try:
            chunk = data_aead.decrypt(nonce, segment, header_hash + b'CHUNK' + index.to_bytes(8, 'big'))
        except InvalidTag as exc:
            raise CryptoError('Zmienione lub uszkodzone dane') from exc
        if output is not None:
            output.write(chunk)
        index += 1


def decrypt_file(source: str | Path, output: str | Path, password: str,
                 keyfile: str | Path | None = None) -> None:
    source, output = _prepare_paths(source, output)
    with _open_checked_file(source) as inp:
        meta, raw_header, header_hash, notice = _read_header(inp)
        digest = _keyfile_digest(Path(keyfile) if keyfile is not None else None)
        if (digest is not None) != meta['keyfile_required']:
            raise CryptoError('Niewłaściwy tryb: wymagany lub zbędny plik klucza')
        wrap_key = _derive_wrap_key(password, _unb64(meta['salt'], 16), digest, version=meta['version'])
        protected = {k: v for k, v in meta.items() if k != 'wrapped_dek'}
        try:
            dek = AESGCM(wrap_key).decrypt(_unb64(meta['wrap_nonce'], 12),
                                            _unb64(meta['wrapped_dek'], 48), _json(protected) + notice)
        except InvalidTag as exc:
            raise CryptoError('Błędny PIN/hasło, plik klucza albo uszkodzone dane') from exc
        data_aead = AESGCM(dek)
        nonce_prefix = _unb64(meta['stream_nonce_prefix'], 4)
        payload_offset = inp.tell()

        # Pass 1: no plaintext file is opened or created if stored ciphertext
        # is already invalid. This also checks the authenticated final marker.
        _decrypt_stream(inp, data_aead, nonce_prefix, header_hash)

        # Pass 2: authentication is repeated in case the source changed.
        # The successful result still creates temporary plaintext on the
        # destination filesystem; use a separately encrypted destination.
        inp.seek(payload_offset)
        _atomic_write(output, lambda out: _decrypt_stream(inp, data_aead,
                                                           nonce_prefix, header_hash, out))