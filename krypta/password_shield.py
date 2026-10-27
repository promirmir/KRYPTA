"""KRYPTA Password Shield / desktop offline secrets vault (development scope).

Reuses the authenticated KRYPTA-FILE/2 envelope, Argon2id and AES-256-GCM
stream format. Never creates a plaintext staging file. Updates write a NEW
encrypted staging file and use a process lock + atomic replace on supported
local filesystems. This is not a password manager security audit, hardware
PIN rate-limiter, independent anti-rollback witness or Android vault.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import secrets
import stat

from .core import (_encrypt_reader, _open_checked_file, _unlock_data_stream,
                   _decrypt_stream, verify_file, CryptoError)

FORMAT = "KRYPTA-SECRETS/1"
MAX_PLAINTEXT_BYTES = 256 * 1024
MAX_ENTRIES = 128
MAX_FIELD_CHARS = 8192


class VaultError(ValueError):
    """Refused unsafe, invalid or unavailable secrets-vault operation."""


def _vault_path(filename: str | Path, *, creating=False) -> Path:
    path = Path(filename)
    if path.suffix.lower() != ".ksecrets":
        raise VaultError("Use a .ksecrets vault")
    if not path.parent.is_dir() or path.parent.is_symlink():
        raise VaultError("Vault parent directory must exist and be non-symlink")
    for ancestor in path.parents:
        if ancestor.is_symlink():
            raise VaultError("Symlink parent paths are forbidden")
    if path.is_symlink() or (not creating and not path.is_file()):
        raise VaultError("Vault must be an existing regular non-symlink file")
    if creating and (path.exists() or path.is_symlink()):
        raise VaultError("Vault already exists; refusing overwrite")
    if not creating:
        info = path.stat(follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise VaultError("Vault must be an unaliased regular file")
        if os.name == "posix" and (info.st_mode & 0o077):
            raise VaultError("Vault access permissions must be private (0600)")
    return path


def _password(value: str):
    # Without real hardware anti-hammering, reject short secrets rather than
    # suggesting that a four-digit PIN protects an offline-copiable vault.
    if type(value) is not str or len(value) < 12:
        raise VaultError("Offline vault requires a passphrase of >=12 characters")


def _encode(doc: dict) -> bytes:
    _validate(doc)
    raw = json.dumps(doc, sort_keys=True, ensure_ascii=True,
                     separators=(",", ":")).encode("ascii")
    if len(raw) > MAX_PLAINTEXT_BYTES:
        raise VaultError("Encrypted vault document exceeds maximum capacity")
    return raw


def _validate(doc):
    if (type(doc) is not dict or set(doc) != {"format", "entries"} or
            doc["format"] != FORMAT or type(doc["entries"]) is not list or
            len(doc["entries"]) > MAX_ENTRIES):
        raise VaultError("Invalid secrets-vault schema")
    names = set()
    for entry in doc["entries"]:
        if type(entry) is not dict or set(entry) != {"title", "username", "secret", "note"}:
            raise VaultError("Invalid vault record")
        for value in entry.values():
            if type(value) is not str or len(value) > MAX_FIELD_CHARS:
                raise VaultError("Vault field exceeds limit")
        name = entry["title"]
        if not name or len(name) > 120 or name.casefold() in names:
            raise VaultError("Duplicate, missing or oversized vault entry title")
        names.add(name.casefold())


def _unique_pairs(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise VaultError("Duplicate JSON vault keys")
        out[k] = v
    return out


def _read(path: Path, password: str, keyfile: str | Path | None) -> tuple[dict, tuple]:
    class Sink:
        def __init__(self):
            self.data = io.BytesIO()
            self.length = 0
        def write(self, block):
            self.length += len(block)
            if self.length > MAX_PLAINTEXT_BYTES:
                raise VaultError("Unbounded decrypted secret record rejected")
            self.data.write(block)

    with _open_checked_file(path) as inp:
        begin = os.fstat(inp.fileno())
        if begin.st_nlink != 1 or (os.name == "posix" and begin.st_mode & 0o077):
            raise VaultError("Vault file permissions are unsafe")
        inp.seek(0)
        disk_digest = hashlib.sha256()
        while data := inp.read(65536):
            disk_digest.update(data)
        inp.seek(0)
        cipher, nonce, aad = _unlock_data_stream(inp, password, keyfile)
        sink = Sink()
        _decrypt_stream(inp, cipher, nonce, aad, sink)
        end = os.fstat(inp.fileno())
        if ((begin.st_dev, begin.st_ino, begin.st_size, begin.st_mtime_ns) !=
                (end.st_dev, end.st_ino, end.st_size, end.st_mtime_ns)):
            raise VaultError("Vault file changed during authentication")
        try:
            doc = json.loads(sink.data.getvalue().decode("ascii"),
                             object_pairs_hook=_unique_pairs)
        except (ValueError, UnicodeError) as exc:
            raise VaultError("Encrypted vault payload is invalid") from exc
        _validate(doc)
        if _encode(doc) != sink.data.getvalue():
            raise VaultError("Noncanonical vault payload rejected")
        return doc, ((begin.st_dev, begin.st_ino), disk_digest.hexdigest())


def _fsync_parent(path):
    if os.name == "posix":
        fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def _lock(path):
    class Lock:
        def __enter__(self):
            self.path = path.with_name(path.name + ".lock")
            flags = (os.O_CREAT | os.O_EXCL | os.O_WRONLY |
                     getattr(os, "O_NOFOLLOW", 0) |
                     getattr(os, "O_CLOEXEC", 0) |
                     getattr(os, "O_BINARY", 0))
            try:
                self.fd = os.open(self.path, flags, 0o600)
            except OSError as exc:
                raise VaultError(
                    "Vault is locked; inspect any stale lock after a crash"
                ) from exc
            self.identity = os.fstat(self.fd)
            return self

        def __exit__(self, *exc):
            os.close(self.fd)
            try:
                current = self.path.stat(follow_symlinks=False)
                if ((current.st_dev, current.st_ino) ==
                        (self.identity.st_dev, self.identity.st_ino)):
                    self.path.unlink()
            except FileNotFoundError:
                pass

    return Lock()


def create_vault(filename: str | Path, password: str,
                 keyfile: str | Path | None = None) -> None:
    _password(password)
    path = _vault_path(filename, creating=True)
    raw = _encode({"format": FORMAT, "entries": []})
    with _lock(path):
        # Exclusive no-clobber publish is implemented by core._atomic_write.
        _encrypt_reader(lambda: io.BytesIO(raw), path, password, keyfile)
        _fsync_parent(path)


def list_entries(filename: str | Path, password: str,
                 keyfile: str | Path | None = None) -> list[str]:
    _password(password)
    path = _vault_path(filename)
    doc, _ = _read(path, password, keyfile)
    return [e["title"] for e in doc["entries"]]


def read_entry(filename: str | Path, password: str, title: str,
               keyfile: str | Path | None = None) -> dict:
    _password(password)
    doc, _ = _read(_vault_path(filename), password, keyfile)
    for item in doc["entries"]:
        if item["title"] == title:
            return dict(item)
    raise VaultError("Vault title not found")


def _mutate(filename, password, keyfile, change):
    _password(password)
    path = _vault_path(filename)
    with _lock(path):
        doc, old = _read(path, password, keyfile)
        change(doc["entries"])
        raw = _encode(doc)
        staged = path.with_name("." + path.name + ".encrypted-"
                                + secrets.token_hex(16))
        try:
            _encrypt_reader(lambda: io.BytesIO(raw), staged, password, keyfile)
            verified = verify_file(staged, password, keyfile)
            if (verified["plaintext_bytes"] != len(raw) or
                    verified["plaintext_sha256"] != hashlib.sha256(raw).hexdigest()):
                raise VaultError("Authenticated post-write verification failed")
            current = _vault_path(path)
            with _open_checked_file(current) as reader:
                new_info = os.fstat(reader.fileno())
                digest = hashlib.sha256()
                while block := reader.read(65536):
                    digest.update(block)
                if (((new_info.st_dev, new_info.st_ino),
                     digest.hexdigest()) != old):
                    raise VaultError("Vault changed concurrently; refusing update")
            # Lock serializes cooperative writers. A malicious same-account
            # writer can still race path replacement; OS isolation is needed.
            os.replace(staged, path)
            _fsync_parent(path)
        finally:
            # Do not remove a third-party substituted path.
            if staged.is_file() and not staged.is_symlink():
                staged.unlink()


def store_entry(filename: str | Path, password: str, title: str,
                username: str, secret: str, note: str = "",
                keyfile: str | Path | None = None) -> None:
    entry = dict(title=title, username=username, secret=secret, note=note)
    def edit(records):
        if any(e["title"].casefold() == title.casefold() for e in records):
            raise VaultError("Entry already exists; overwriting secrets is prohibited")
        records.append(entry)
    _mutate(filename, password, keyfile, edit)


def remove_entry(filename: str | Path, password: str, title: str,
                 keyfile: str | Path | None = None) -> None:
    def edit(records):
        kept = [e for e in records if e["title"] != title]
        if len(kept) == len(records):
            raise VaultError("Vault title not found")
        records[:] = kept
    _mutate(filename, password, keyfile, edit)
