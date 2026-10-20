# KRYPTA Android — private UI research scaffold

This Android native Java application is a **non-security, non-encrypting UI prototype**.
It has **no** `INTERNET`, storage, or special permissions and **does not** change Android FBE, the lock screen or any protected files.

The build is an internally signed **debug APK**, not a production distribution. Android debug signing keys do not establish publisher identity.

For experimental local development:

```sh
cd android
gradle :app:assembleDebug
```

Use the private GitHub Actions `KRYPTA / Android UI research APK` to obtain a build artifact; if CI is successful download `KRYPTA-Android-debug-UI-ONLY` from that run's Artifacts section. This is **not** a working Android encryption release.

Never describe this UI prototype as full-device encryption. Android must use device-specific system FBE, Gatekeeper/Weaver and Android Keystore integration for meaningful protection.