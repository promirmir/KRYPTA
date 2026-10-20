"""Real Tk widget smoke test; skip in headless environments without DISPLAY."""
import os
import pytest


@pytest.mark.skipif(os.name != 'nt' and not os.environ.get('DISPLAY'), reason='No Tk display')
def test_all_desktop_languages_keep_correct_security_warnings_and_actions():
    from krypta.gui import KryptaApp
    from krypta.i18n import LANGUAGES
    app = KryptaApp()
    try:
        for code, name in LANGUAGES.items():
            app.language_name.set(name)
            app._language_changed()
            app.update_idletasks()
            assert app.language_code == code
            assert app._t('file_vault') in app.module_buttons[0]['text']
            assert app._t('advice_empty') in app.risk['text']
            app.mode.set('encrypt')
            app.password.set('1234')
            app.update_idletasks()
            assert app._t('advice_short') in app.risk['text']
            app._show_module(2)
            assert app._t('future_system') in app.future_copy['text']
            app._show_module(0)
            app.mode.set('info')
            app.update_idletasks()
            assert app._t('inspect_action') == app.action['text']
            app.mode.set('encrypt')
            app.password.set('')
            app.update_idletasks()
    finally:
        app.destroy()