"""Static Android source, permission and security-statement contract checks."""
from pathlib import Path
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
ANDROID = ROOT / "android/app"
SRC = ANDROID / "src/main/java/io/krypta/research"
JAVA = (SRC / "MainActivity.java").read_text(encoding="utf-8")
KEY = (SRC / "AndroidVaultKey.java").read_text(encoding="utf-8")
FORMAT = (SRC / "VaultFormat.java").read_text(encoding="utf-8")
MANIFEST = (ANDROID / "src/main/AndroidManifest.xml").read_text(encoding="utf-8")


def test_android_ui_exposes_selected_file_vault_without_claiming_device_encryption():
    assert "getString(R.string.vault_warning)" in JAVA
    assert "getString(R.string.vault_encrypt)" in JAVA
    assert "getString(R.string.vault_decrypt)" in JAVA
    assert "VaultFormat.encrypt(" in JAVA
    assert "VaultFormat.decrypt(" in JAVA
    assert "AndroidVaultKey.getOrCreate(" in JAVA
    assert "Intent.ACTION_OPEN_DOCUMENT" in JAVA
    assert "Intent.ACTION_CREATE_DOCUMENT" in JAVA
    # No privileged disk writes or access to other apps' private storage.
    assert "android.permission.INTERNET" not in MANIFEST
    assert "android.permission.MANAGE_EXTERNAL_STORAGE" not in MANIFEST
    assert "android.permission.READ_EXTERNAL_STORAGE" not in MANIFEST
    assert 'android:allowBackup="false"' in MANIFEST


def test_android_device_key_requires_user_credential_and_android_keystore():
    assert 'KeyStore.getInstance("AndroidKeyStore")' in KEY
    assert "setUserAuthenticationRequired(true)" in KEY
    assert "AUTH_DEVICE_CREDENTIAL" in KEY
    assert 'setRandomizedEncryptionRequired(true)' in KEY
    assert "setKeySize(256)" in KEY


def test_android_file_format_has_independent_authenticated_end_marker():
    assert '"KRYPTA-MOBILE/1' in FORMAT
    assert 'new GCMParameterSpec(128,' in FORMAT
    assert "aad(end, header, index, 0, true)" in FORMAT
    assert "input.read() != -1" in FORMAT
    assert "MAX_RECORDS" in FORMAT


def test_android_all_locales_warn_about_scope_and_lost_keystore_key():
    base = ANDROID / "src/main/res"
    folders = ("values", "values-pl", "values-ru", "values-zh-rCN",
               "values-es", "values-ar", "values-hi", "values-pt",
               "values-fr", "values-de", "values-in")
    required = {"vault_warning", "vault_body", "vault_encrypt", "vault_decrypt",
                "vault_failed", "vault_need_lock", "vault_auth_body"}
    for folder in folders:
        root = ET.parse(base / folder / "vault.xml").getroot()
        items = {node.attrib["name"]: node.text for node in root.findall("string")}
        assert required <= set(items)
        assert all(items[name] and items[name].strip() for name in required)
        assert "Android Keystore" in items["vault_warning"]
        assert "KRYPTA-MOBILE/1" in items["vault_body"]


def test_android_language_selector_and_rtl():
    assert "createConfigurationContext(config)" in JAVA
    assert 'getSharedPreferences("krypta-ui", MODE_PRIVATE)' in JAVA
    assert "View.LAYOUT_DIRECTION_RTL" in JAVA
    assert 'Locale.forLanguageTag("zh".equals(selected) ? "zh-CN" : selected)' in JAVA
