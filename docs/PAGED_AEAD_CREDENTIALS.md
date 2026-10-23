# KRYPTA — niezależne hasło i klucz odzyskiwania dla AEAD v2

Moduł: research/paged_aead_credentials.py. Format: KRYPTA-PAGED-AEAD-KEYS/1, niezależny od PVKEY/1.

- Własny losowy 32-bajtowy klucz woluminu jest szyfrowany osobno pod hasłem (Argon2id: 64 MiB, 3 iteracje, p=2 + HKDF-SHA256) oraz losowym 32-bajtowym sekretem odzyskiwania (osobny HKDF-SHA256).
- Dwa odrębne losowe nonce AES-256-GCM; uwierzytelnione powiązanie z identyfikatorem konkretnego woluminu, formatem, solą i rodzajem klucza.
- Provisioning wymaga poprawnego niezależnego receipt, otwiera obraz wyłącznie do odczytu, uwierzytelnia wszystkie aktualne sektory, tworzy dwa nowe pliki bez nadpisania i ponownie sprawdza hasło oraz klucz odzyskiwania.
- Odblokowanie weryfikuje zarówno kopertę kluczy, jak i rzeczywisty nagłówek i receipt woluminu. Recovery nie zakłada znajomości hasła. Klucz odzyskiwania należy przechowywać na niezależnym nośniku.
- Za krótki PIN (np. 4 cyfry) zostaje odrzucony w trybie hasłowym bez niezależnego sekretu sprzętowego i ograniczania prób. Wymóg charter odnośnie PIN pozostaje **niezrealizowany**.
- Wspólne mechanizmy bezpiecznego zapisu plików z research/paged_keys.py; klucze, nonce, format i domeny są odrębne. Windows ACL i bezpieczeństwo pamięci wymagają osobnego audytu.

**Granice:** tylko zwykłe obrazy testowe .kdevtest, bez obsługi dysków fizycznych i bez aktualizacji produkcyjnego EXE/APK. Brak TPM, ochrony przed pełnym rollback koperty/obrazu oraz bezpiecznego usuwania kopii starych kluczy. Działanie po kompakcji do nowego woluminu wymaga utworzenia **nowego** zestawu powiązanego z nowym ID.
