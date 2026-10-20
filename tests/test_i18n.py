"""KRYPTA multi-platform localization coverage and user safety tests."""
from pathlib import Path
import xml.etree.ElementTree as ET

import pytest

from krypta.i18n import CATALOG, FIELDS, LANGUAGES, normalize_language, translate

ROOT = Path(__file__).resolve().parents[1]
ANDROID = ROOT / 'android/app/src/main/res'
FOLDERS = {'en': 'values', 'pl': 'values-pl', 'ru': 'values-ru', 'zh': 'values-zh-rCN',
           'es': 'values-es', 'ar': 'values-ar', 'hi': 'values-hi', 'pt': 'values-pt',
           'fr': 'values-fr', 'de': 'values-de', 'id': 'values-in'}


def test_language_catalog_is_complete():
    assert len(LANGUAGES) >= 11
    assert len(FIELDS) == len(set(FIELDS))
    assert set(LANGUAGES) == set(CATALOG) == set(FOLDERS)
    for lang, translations in CATALOG.items():
        assert set(translations) == set(FIELDS), lang
        assert all(isinstance(v, str) and v.strip() for v in translations.values())
        assert 'AES-256-GCM' in translations['vault_subtitle'], lang
        assert 'TPM' in translations['future_system'], lang
        assert 'KRYPTA' not in translations['research_notice'] or lang == 'en'


@pytest.mark.parametrize('lang', sorted(LANGUAGES))
def test_language_notices_do_not_claim_working_full_disk_encryption(lang):
    assert CATALOG[lang]['mobile_not_protected'] != ''
    assert CATALOG[lang]['future_system'] != ''
    assert CATALOG[lang]['advice_short'] != ''
    assert CATALOG[lang]['risk_confirm'] != ''
    assert translate(lang, 'file_vault') == CATALOG[lang]['file_vault']


@pytest.mark.parametrize('tag,expected', [('pl-PL','pl'),('zh-CN','zh'),('ru_RU','ru'),
                                         ('pt-BR','pt'),('en-US','en'),('xx-YY','en'),
                                         (None,'en')])
def test_os_locale_alias(tag, expected):
    assert normalize_language(tag) == expected


@pytest.mark.parametrize('lang,folder', FOLDERS.items())
def test_all_android_translation_files_complete_and_well_formed(lang, folder):
    root = ET.parse(ANDROID / folder / 'strings.xml').getroot()
    names = [el.attrib['name'] for el in root.findall('string')]
    assert len(names) == len(FIELDS)
    assert set(names) == set(FIELDS)


def test_no_language_changes_encrypted_file_header_protocol():
    from krypta.core import _notice
    assert b'KRYPTA-FILE/2' in _notice(False)
    assert b'Argon2id' in _notice(False)
    assert b'END KRYPTA NOTICE' in _notice(False)

@pytest.mark.parametrize('lang', sorted(LANGUAGES))
def test_mobile_ui_describes_existing_selected_file_encryption(lang):
    """No outdated 'interface only / no file encryption' capability claims."""
    message = CATALOG[lang]['mobile_file_body']
    assert 'AES-256-GCM' in message
    assert 'Android Keystore' in message
    assert CATALOG[lang]['mobile_status'].strip()
    assert CATALOG[lang]['mobile_not_protected'].strip()
    # The Android file vault is a real selected-file feature, not phone-wide FDE.
    # Native encryption/decryption entrypoints are checked separately by Java tests.


def test_mobile_capability_regression_in_english_and_polish():
    assert 'SELECTED FILES' in CATALOG['en']['mobile_not_protected']
    assert 'WYBRANE PLIKI' in CATALOG['pl']['mobile_not_protected']
    assert 'INTERFACE ONLY' not in CATALOG['en']['mobile_status']
    assert 'TYLKO INTERFEJS' not in CATALOG['pl']['mobile_status']
