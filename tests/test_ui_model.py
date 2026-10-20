from krypta.ui_model import password_warning


def test_short_pin_warns_about_offline_attack():
    assert 'OFFLINE BRUTE FORCE' in password_warning('1', False)
    assert 'OFFLINE BRUTE FORCE' in password_warning('1234', False)


def test_keyfile_message_does_not_claim_hardware_enforcement():
    assert 'NIE jest sprzętowe' in password_warning('1', True)