"""Password Shield desktop: authenticated record tests, no plaintext files."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from krypta.core import CryptoError, generate_keyfile
from krypta.password_shield import (
    VaultError, create_vault, list_entries, read_entry,
    store_entry, remove_entry, _encode
)

MASTER = "Unique long test passphrase 2026!"


@pytest.fixture
def vault(tmp_path):
    name = tmp_path / "secrets.ksecrets"
    keyfile = tmp_path / "independent.secret"
    generate_keyfile(keyfile)
    create_vault(name, MASTER, keyfile)
    return name, keyfile


def test_create_add_read_delete_never_publishes_plaintext(vault):
    name, key = vault
    assert list_entries(name, MASTER, key) == []
    store_entry(name, MASTER, "Bank", "login@example.test",
                "must-never-be-in-cleartext", "not for production",
                keyfile=key)
    assert list_entries(name, MASTER, key) == ["Bank"]
    entry = read_entry(name, MASTER, "Bank", keyfile=key)
    assert entry["username"] == "login@example.test"
    assert entry["secret"] == "must-never-be-in-cleartext"
    ciphertext = name.read_bytes()
    assert b"must-never-be-in-cleartext" not in ciphertext
    assert b"login@example.test" not in ciphertext
    assert b"Bank" not in ciphertext
    assert not list(name.parent.glob(".*encrypted-*"))
    remove_entry(name, MASTER, "Bank", keyfile=key)
    assert list_entries(name, MASTER, key) == []
    assert not list(name.parent.glob("*.lock"))


def test_wrong_secret_tampering_and_nonmatching_key_rejected(vault, tmp_path):
    name, key = vault
    before = name.read_bytes()
    with pytest.raises(CryptoError):
        list_entries(name, "Wrong long password 2026!", key)
    other_key = tmp_path / "another.key"
    generate_keyfile(other_key)
    with pytest.raises(CryptoError):
        list_entries(name, MASTER, other_key)
    assert name.read_bytes() == before
    tampered = bytearray(before)
    tampered[-1] ^= 0x20
    name.write_bytes(tampered)
    with pytest.raises(CryptoError):
        list_entries(name, MASTER, key)


def test_existing_vault_duplicate_entries_no_silent_overwrite(vault):
    name, key = vault
    store_entry(name, MASTER, "Example", "first", "original", keyfile=key)
    prior = name.read_bytes()
    with pytest.raises(VaultError, match="already exists"):
        store_entry(name, MASTER, "eXAMple", "second", "changed", keyfile=key)
    assert name.read_bytes() == prior
    assert read_entry(name, MASTER, "Example", keyfile=key)["secret"] == "original"
    with pytest.raises(VaultError, match="not found"):
        remove_entry(name, MASTER, "missing", keyfile=key)
    assert name.read_bytes() == prior


def test_short_pin_and_corrupt_schema_rejected_before_write(tmp_path):
    name = tmp_path / "bad.ksecrets"
    with pytest.raises(VaultError, match="12"):
        create_vault(name, "1234")
    assert not name.exists()
    with pytest.raises(VaultError):
        _encode({"format": "OTHER", "entries": []})
    with pytest.raises(VaultError):
        _encode({"format": "KRYPTA-SECRETS/1", "entries": [{
            "title": "x", "username": "", "secret": "", "note": ""
        }, {"title": "X", "username": "", "secret": "", "note": ""
        }]})


def test_existing_vault_cannot_be_created_over(vault):
    name, key = vault
    before = name.read_bytes()
    with pytest.raises(VaultError, match="already exists"):
        create_vault(name, MASTER, key)
    assert name.read_bytes() == before


def test_failed_encrypted_publish_keeps_previous_vault(vault, monkeypatch):
    from krypta import password_shield as service
    name, key = vault
    before = name.read_bytes()
    original = service.os.replace

    def reject_publish(source, target):
        assert b"do-not-leak" not in Path(source).read_bytes()
        assert Path(target) == name
        raise OSError("simulated storage error")

    monkeypatch.setattr(service.os, "replace", reject_publish)
    with pytest.raises(OSError, match="storage error"):
        store_entry(name, MASTER, "Title", "user", "do-not-leak",
                    keyfile=key)
    assert name.read_bytes() == before
    assert list_entries(name, MASTER, key) == []
    assert not list(name.parent.glob(".*encrypted-*"))
    assert not name.with_name(name.name + ".lock").exists()
    monkeypatch.setattr(service.os, "replace", original)


def test_locked_vault_refuses_update_without_touching_content(vault):
    name, key = vault
    before = name.read_bytes()
    lock = name.with_name(name.name + ".lock")
    lock.write_bytes(b"locked by another writer")
    with pytest.raises(VaultError, match="locked"):
        store_entry(name, MASTER, "Title", "user", "secret", keyfile=key)
    assert name.read_bytes() == before
    assert lock.read_bytes() == b"locked by another writer"


def test_wrong_key_never_advances_or_cleans_another_lock(vault):
    name, key = vault
    old = name.read_bytes()
    with pytest.raises(CryptoError):
        store_entry(name, "Incorrect long passphrase!", "Name", "", "s", keyfile=key)
    assert name.read_bytes() == old
    assert not name.with_name(name.name + ".lock").exists()


@pytest.mark.skipif(os.name == "nt", reason="Windows symlink permissions vary")
def test_symlink_to_vault_and_group_readable_permissions_rejected(vault, tmp_path):
    name, key = vault
    link = tmp_path / "alias.ksecrets"
    link.symlink_to(name)
    with pytest.raises(VaultError):
        list_entries(link, MASTER, key)
    name.chmod(0o644)
    with pytest.raises(VaultError, match="private"):
        list_entries(name, MASTER, key)
