"""Tests for fail-closed *advisory* TPM reporting (not key security)."""
import copy
import pytest
from krypta.hardware_readiness import assess_windows_readiness


def report():
    return {
        'schema': 'KRYPTA-TPM-READINESS/1',
        'tpm': {'present': True, 'ready': True, 'locked_out': False},
        'platform_crypto_provider': {'can_open': True},
        'secure_boot': {'enabled': True},
        'security_assurance': {'pin_anti_hammering_verified': False},
    }


def test_best_case_still_cannot_claim_pin_protection():
    a = assess_windows_readiness(report())
    assert a.device_key_prototype_possible
    assert not a.pin_anti_hammering_verified
    assert not a.boot_integrity_binding_verified
    assert a.evidence == 'read_only_untrusted_inventory'


@pytest.mark.parametrize('section,key,value', [
    ('tpm', 'present', False), ('tpm', 'ready', False),
    ('tpm', 'locked_out', True), ('tpm', 'locked_out', None),
    ('platform_crypto_provider', 'can_open', False),
    ('platform_crypto_provider', 'can_open', 'true'),
])
def test_prototype_fails_closed(section, key, value):
    r = report(); r[section][key] = value
    assert not assess_windows_readiness(r).device_key_prototype_possible


def test_unknown_secure_boot_remains_unverified():
    r = report(); r['secure_boot']['enabled'] = None
    a = assess_windows_readiness(r)
    assert a.device_key_prototype_possible  # ability to *research* hardware keys only
    assert not a.secure_boot_confirmed
    assert not a.boot_integrity_binding_verified


def test_untrusted_input_cannot_assert_pin_verified():
    r = report(); r['security_assurance']['pin_anti_hammering_verified'] = True
    a = assess_windows_readiness(r)
    assert a.pin_anti_hammering_verified is False


@pytest.mark.parametrize('invalid', [None, {}, {'schema': 'x'}, {'schema':'KRYPTA-TPM-READINESS/1'},
     {'schema':'KRYPTA-TPM-READINESS/1','tpm':True,'platform_crypto_provider':{},'secure_boot':{}}])
def test_invalid_report_rejected(invalid):
    with pytest.raises(ValueError):
        assess_windows_readiness(invalid)


def test_report_has_no_secrets_or_pin_value():
    a = assess_windows_readiness(report()).as_dict()
    assert 'pin' not in a and 'key' not in a
    assert 'PIN' in ' '.join(a['notes'])