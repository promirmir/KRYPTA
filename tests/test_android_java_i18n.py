"""Static Android Java/resource safety contract checks (not APK device tests)."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
JAVA = (ROOT / 'android/app/src/main/java/io/krypta/research/MainActivity.java').read_text(encoding='utf-8')
MANIFEST = (ROOT / 'android/app/src/main/AndroidManifest.xml').read_text(encoding='utf-8')


def test_android_ui_does_not_claim_device_encryption():
    assert 'getString(R.string.mobile_not_protected)' in JAVA
    assert 'NO ENCRYPTION IS IMPLEMENTED' in JAVA
    assert 'android.permission.INTERNET' not in MANIFEST.replace('<!-- No network, storage, or privileged permissions: UI research application only. -->','')


def test_android_language_selector_and_rtl():
    assert 'createConfigurationContext(config)' in JAVA
    assert 'getSharedPreferences("krypta-ui", MODE_PRIVATE)' in JAVA
    assert 'View.LAYOUT_DIRECTION_RTL' in JAVA
    assert 'Locale.forLanguageTag("zh".equals(selected) ? "zh-CN" : selected)' in JAVA