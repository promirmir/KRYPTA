# KRYPTA / localization matrix (research alpha)

**Current languages**: English (`en`), Polish (`pl`), Russian (`ru`), Simplified Chinese (`zh`), Spanish (`es`), Arabic (`ar`), Hindi (`hi`), Portuguese (`pt`), French (`fr`), German (`de`) and Indonesian (`id`).

## Desktop Windows / Linux

`krypta/i18n.py` contains semantic UI message identifiers and corresponding translations. The desktop UI uses a language picker on the main screen; switching languages does not change the currently selected source file, target file, keyfile or operating mode. Default language follows the operating-system locale when supported and otherwise falls back to English. Desktop selection applies to the current process (it is not stored on disk).

The safety banner, the **short PIN offline guessing** warning and the **modules not implemented** warning are mandatory for every locale. Language choice does not change any cryptographic algorithm, key, password, file format, or security policy. Unicode display depends on fonts installed on the host operating system. Windows and Linux may need the appropriate system fonts for Arabic, Simplified Chinese and Devanagari scripts; no font files are redistributed here.

## Android

The APK uses Android `strings.xml` resources generated from exactly the same semantic text catalogue by `tools/sync_android_strings.py`. It follows the phone's locale by default and offers a language selector, stored privately as a UI-only preference. Arabic uses right-to-left content layout and Android system font fallback. The APK still **does not encrypt files or the phone**.

**Important:** Android build generation must run the consistency check before `Gradle` compilation:

```bash
python tools/sync_android_strings.py --check
```

To revise translation strings, edit `krypta/i18n.py`, run `python tools/sync_android_strings.py` from repository root, and review changes to `android/app/src/main/res/values*/strings.xml` before committing.

The human-readable `.kry` file header **remains invariant English ASCII** (`KRYPTA-FILE/2`), deliberately independent of the UI language to ensure cross-platform compatibility and avoid changing authenticated ciphertext metadata. Human review of translations, fonts and screen reader accessibility is required before public security release. Automated tests check presence and consistency but cannot certify translation quality.

## No misleading guarantees

Localization does not implement OS full-disk encryption, TPM-based PIN rate limiting, or Android Keystore protections. Short PINs without independent securely protected secrets remain vulnerable to offline guessing. Localized text describes current functionality, not future aspirations as present guarantees.