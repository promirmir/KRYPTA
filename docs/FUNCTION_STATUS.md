# KRYPTA — stan funkcji i droga do wersji 1.0

**Stan na 23.10.2026.** Ten plik jest aktualną tabelą postępu. Pierwotne wymagania pozostają w [PROJECT_CHARTER.md](PROJECT_CHARTER.md). Obowiązkowe kryteria ukończenia znajdują się w [PRODUCT_ACCEPTANCE.md](PRODUCT_ACCEPTANCE.md). Aktualne pliki dla użytkowników: [GitHub Releases](https://github.com/promirmir/KRYPTA/releases).

**Znaczenie statusów:** "Działa w dev" = dostępne w uruchamialnym wydaniu rozwojowym, nie oznacza gotowości produkcyjnej. "Test CI" = istnieje kod i kontrolowane testy, ale funkcja nie jest jeszcze użyteczna dla ogólnego użytkownika. "Brak" = wymaganie pierwotnego produktu nie zostało spełnione.

## Co działa obecnie

| Obszar | Windows | Linux | Android | Ważne ograniczenie |
|---|---|---|---|---|
| Graficzny File Vault — szyfrowanie i odszyfrowywanie wybranych plików | Działa w dev EXE | Działa w dev ELF | Działa w debug APK | Nie przechwytuje automatycznie zapisów wszystkich programów |
| Własny zaszyfrowany format PVIMG/1 i PFS/2 | Działa w Volume Lab na .kpv | Działa w Volume Lab na .kpv | Brak | Maks. 32 MiB/pliki, 128 plików, obraz testowy, nie wolumin fizyczny |
| Hasło oraz niezależny klucz do odzyskiwania PFS/2 | Działa w Volume Lab | Działa w Volume Lab | Brak wspólnego PFS/2 | PVKEY/1 wymaga długiego hasła; brak sprzętowego ogranicznika krótkiego PIN-u |
| Import pojedynczego i wielu plików, eksport, weryfikacja PFS/2 | Działa w Volume Lab | Działa w Volume Lab | Brak | „Dodaj wiele”: kilka nowych plików i jedna zatwierdzona transakcja/receipt, maks. 32 MiB łącznie, 128 plików w woluminie; nadal bez montowania zapisu |
| Rotacja klucza danych przez nowy zaszyfrowany obraz | Działa w Volume Lab | Działa w Volume Lab | Brak | Stare kopie i stare klucze nie są automatycznie unieważniane |
| Ratunkowy pełny eksport aktualnych plików PFS/2 bez GUI | Działa w Rescue EXE (dev) | Działa w Rescue ELF (dev) | Brak | Źródłowy obraz tylko do odczytu; wynik jest jawny |
| Analiza dziennika, historii receipt i symulacji przerwań | Działa w Volume Lab (R/O) / testach | Działa w Volume Lab (R/O) / testach | Brak | Historia nie potwierdza automatycznie świeżości nowszego stanu |
| Zewnętrznie zapieczętowany punkt zaufania receipt | Volume Lab GUI (od kolejnego wydania) + testy | Volume Lab GUI (od kolejnego wydania) + testy | Brak | Użytkownik ręcznie dostarcza wcześniejszy zaufany receipt / niezależny SHA-256 seal; bez TPM, automatycznej aktualizacji ani odporności na rollback całego magazynu |
| Montowanie FUSE dla zaszyfrowanego obrazu | — | Test CI / osobny program | — | Niepełna zgodność POSIX, nieobsługiwane realne partycje |
| WinFsp: montowanie, odczyt, odmowa zapisu | Test na natywnym Windows CI / osobny R/O helper | — | — | Wydanie użytkowe nie montuje woluminu do zapisu |
| WinFsp: buforowany zapis i commit na polecenie flush | Etap testowy na tymczasowym .kpv; wymaga walidacji | — | — | **Nie jest zintegrowane z wydanym EXE; nie wolno podłączać rzeczywistych dysków** |
| Linux/Windows — wymiana tego samego zaszyfrowanego obrazu PFS/2 | Test CI PASS | Test CI PASS | Brak | Integracja z GUI nie oznacza przenoszenia zaufanego stanu i kluczy |
| Rozpoznawanie rzeczywistych fizycznych dysków i ich metadanych | Kod + CI PASS | Kod + CI PASS | Brak | Tylko odczyt metadanych; brak otwierania i szyfrowania urządzeń, zawsze write_authorized=false |
| Testowy zaszyfrowany silnik sektorowy AES-256-GCM, COW, weryfikacja receipt | Test CI PASS (PR #64) | Test CI PASS (PR #64) | Brak | Tylko zwykły obraz .kdevtest, do 32 sektorów logicznych, bez sterownika fizycznego dysku i zabezpieczenia klucza |
| Stronicowany silnik AEAD v2: adresowanie 1024 sektorów, zapis bajtowy i transakcje COW | Test CI PASS (PR #67) | Test CI PASS (PR #67) | Brak | Wyłącznie zaszyfrowany obraz testowy .kdevtest; 4 MiB przestrzeni logicznej, brak sterownika nośnika fizycznego |
| Kompakcja i odzyskiwanie przestrzeni po zapisach v2 | Test CI PASS (PR #68) | Test CI PASS (PR #68) | Brak | Zweryfikowane kopiowanie do NOWEGO obrazu, bez nadpisania źródła; brak garbage collection na stałym fizycznym dysku |
| Argon2id + oddzielny losowy klucz recovery dla sektora v2 | Kod i testy PR #69 | Kod i testy PR #69 | Brak | Osobna koperta związana z ID woluminu i receipt; nadal bez TPM, krótkiego PIN-u i integracji z głównym programem |
| Diagnostyka kandydatów do odzyskania sektora po awarii | W kodzie PR #65, CI do weryfikacji | W kodzie PR #65, CI do weryfikacji | Brak | Tylko odczyt, bez wydawania zaufanego receipt i bez automatycznej zgody na dalszy zapis |
| Szyfrowanie całego dysku, partycji, nośnika USB/SSD/HDD | Brak | Brak | Brak | Niezbędne bezpieczne sterowniki/adaptery urządzeń, przywracanie po awarii, klucze i testy rzeczywistych nośników |
| Szyfrowanie dysku systemowego i rozruchu | Brak | Brak | Zwykły APK nie ma uprawnień do podmiany systemowego FBE | Nie wolno reklamować jako istniejącej funkcji |
| Password Shield — osobny sejf haseł | Brak potwierdzonego kompletnego modułu | Brak potwierdzonego kompletnego modułu | Brak potwierdzonego kompletnego modułu | Wymagany przez Project Charter |
| Krótki PIN wsparty nieeksportowalnym sekretem sprzętowym | Brak | Brak | Brak rozwiązania międzyplatformowego | Krótki PIN bez silnego sprzętowego czynnika jest podatny na zgadywanie offline |
| Niezależny audyt i podpisane wydanie produkcyjne | Brak | Brak | Brak | Nie deklarować gotowości wojskowej, certyfikacji ani odporności na wszystkie ataki |

## Co trzeba zrobić — bez zmiany pierwotnego celu

1. **Windows, priorytet krytyczny:** transakcyjny WinFsp read/write z jednym writerem, poprawnymi semantykami flush/close, blokadą stanu niepewnego, testami Windows API, bezpieczeństwa ACL, współbieżności i odmontowania. Dopiero później użytkowe montowanie zwykłych obrazów; fizyczne nośniki dopiero po oddzielnych bramkach bezpieczeństwa.
2. **Linux, priorytet krytyczny:** uzupełnić zapis montowany FUSE PFS/2, hierarchiczne katalogi, uprawnienia, nazwy, blokady, losowe I/O oraz deterministyczne odmontowanie. Zgodność obrazu i receipt z Windows.
3. **Trwałość i odzyskiwanie:** niezależny, odporny na cofnięcie stan zaufania (TPM/witness + wersjonowanie), testy przerwania w każdym punkcie commitu, realne awarie i niezależne odtwarzanie na drugim komputerze. Opracować procedurę rozwiązania utraconego potwierdzenia zapisu bez cichego przyjęcia nowej wersji.
4. **Pojemność:** odejść od laboratoryjnych limitów PFS/2, dodać skalowalność katalogów, alokację przestrzeni, kompakcję i formatowanie osobnych woluminów danych z bezpiecznymi barierami.
5. **Nośniki i całe dyski:** dopiero po stabilnym montowaniu plikowego obrazu wdrożyć testowe partycje/USB w odizolowanym środowisku, z kopiami zapasowymi i odzyskiwaniem; dyski systemowe i boot jeszcze później.
6. **Android:** opracować przenośny format plików i interoperacyjność z desktopem, pełny test odzyskania kluczy na innym telefonie i podpisane APK. Ochrona całego urządzenia wymaga osobnej, uprzywilejowanej integracji z OS.
7. **Sejf haseł i krótki PIN:** bezpieczny osobny Password Shield, weryfikowane odblokowanie i rzeczywisty sprzętowy limit prób; brak deklarowania bezpieczeństwa krótkiego PIN-u bez takiego mechanizmu.
8. **Dystrybucja:** instalatory i podpisy, aktualizacje, testy różnych wersji OS, kontrola zależności, fuzzing, benchmarking, audyt niezależny, plan migracji/odtwarzania i dopiero potem wersja 1.0.

## Dalszy postęp silnika nośników v2

- [PR #67](https://github.com/promirmir/KRYPTA/pull/67): stronicowane uwierzytelnione metadane oraz częściowe zapisy bajtowe dla izolowanego formatu v2; CI PASS.
- [PR #68](https://github.com/promirmir/KRYPTA/pull/68): weryfikowana kompakcja poza oryginalnym nośnikiem; CI PASS.
- [PR #69](https://github.com/promirmir/KRYPTA/pull/69): koperta hasła Argon2id i niezależny sekret odzyskiwania v2; wyniki CI tego PR stanowią oddzielną bramkę.
- **Bez zmian w statusie głównego celu:** szyfrowanie rzeczywistych fizycznych dysków, partycji i dysków systemowych nie jest wdrożone.

## Aktualne dowody kamieni milowych P0 (23.10.2026)

- [PR #63](https://github.com/promirmir/KRYPTA/pull/63): sektorowy transport wyłącznie na zwykłym pliku testowym, nie fizycznym nośniku.
- [PR #64](https://github.com/promirmir/KRYPTA/pull/64): AES-256-GCM dla sektorów, dwa uwierzytelnione sloty root, zapis COW i testy przerwania operacji; CI Windows/Linux PASS. Szczegóły: [SEALED_SECTOR_IMAGE.md](SEALED_SECTOR_IMAGE.md).
- [PR #65](https://github.com/promirmir/KRYPTA/pull/65): osobna read-only analiza kandydatów do odzyskania, bez automatycznego zaufania. Szczegóły: [SEALED_SECTOR_FORENSIC_REVIEW.md](SEALED_SECTOR_FORENSIC_REVIEW.md). Status CI jest niezależny od wyniku PR #64.
- Wymaganie końcowe pozostaje bez zmian: **szyfrowanie rzeczywistego fizycznego dysku nie jest gotowe**. Nowe moduły tylko redukują ryzyko przed etapem sprzętowym.

## Dyscyplina wydań

- Każda zmiana oznaczona jako "Działa" wymaga konkretnych testów, a zmiana statusu powinna odnosić się do PR/CI.
- **GitHub Releases** to miejsce udostępniania EXE, ELF i APK. Dev/debug buildy są rzeczywistymi aplikacjami, ale nadają się jedynie do testowania na kopiach danych.
- Same kompilacje, funkcjonalne GUI, syntetyczne awarie i zielone CI nie zamykają kryteriów [1.0](PRODUCT_ACCEPTANCE.md). Nie usuwamy brakujących funkcji z listy przez zmianę nazwy lub zakresu projektu.
- W tym samym momencie zawsze utrzymywać aktualne README (pobieranie), ten rejestr (zakres), PRODUCT_ACCEPTANCE (kryteria) oraz SECURITY_STATUS (szczegółowe dowody).

## Physical disks: first read-only integration gate

The KRYPTA CLI now includes `python -m krypta physical-disks` for Windows and Linux. It lists physical disk identities, sizes, basic boot/mount indicators and candidate status using OS inventory commands only. Every disk is **write_authorized: false**: this stage deliberately performs no raw-device open, partitioning or encryption. Linux nested mounted partitions are flagged; Windows volume dependency data is incomplete and is always treated as UNKNOWN for raw-write approval. This is a necessary but **not sufficient** foundation for the requested real USB/SSD/HDD whole-volume encryption. The original P0 device goal remains **NOT IMPLEMENTED** until actual native mount/write, recovery, hot-unplug and hardware tests pass.
