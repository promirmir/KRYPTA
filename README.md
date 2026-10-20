# KRYPTA

**System szyfrowania plików i rozwijany własny silnik zaszyfrowanych woluminów.** Windows · Linux · Android.

KRYPTA działa niezależnie, bez obowiązkowego konta. Aplikacje na Windows, Linux i Android umożliwiają lokalne szyfrowanie oraz odszyfrowywanie **wskazanych plików**. Rozwój obejmuje także własne zaszyfrowane woluminy, system plików, odzyskiwanie oraz zabezpieczanie kluczy.

## 📥 Pobierz aplikację

**[ZOBACZ WSZYSTKIE PLIKI DO POBRANIA — GitHub Releases](https://github.com/promirmir/KRYPTA/releases)**

**Bezpośrednie pliki z potwierdzonego wydania [krypta-dev-2-1](https://github.com/promirmir/KRYPTA/releases/tag/krypta-dev-2-1) (20.10.2026):**

| System | Plik do pobrania | Główna funkcja |
|---|---|---|
| 🪟 **Windows 10/11 x64** | **[KRYPTA-Windows-x64.exe](https://github.com/promirmir/KRYPTA/releases/download/krypta-dev-2-1/KRYPTA-Windows-x64.exe)** | Graficzny File Vault — szyfrowanie i odszyfrowywanie wybranych plików |
| 🐧 **Linux x64** | **[KRYPTA-Linux-x64](https://github.com/promirmir/KRYPTA/releases/download/krypta-dev-2-1/KRYPTA-Linux-x64)** | Graficzny File Vault; dodatkowy kod systemu plików i montowania FUSE |
| 🤖 **Android** | **[KRYPTA-Android-debug.apk](https://github.com/promirmir/KRYPTA/releases/download/krypta-dev-2-1/KRYPTA-Android-debug.apk)** | Szyfrowanie wybranych dokumentów z kluczem chronionym przez Android Keystore |

Powyższe linki pobierają bezpośrednio pliki z potwierdzonego wydania. Nowsze wersje znajdziesz na [stronie wszystkich wydań](https://github.com/promirmir/KRYPTA/releases). Załączone pliki z rozszerzeniem .sha256 pozwalają sprawdzić integralność pobranych plików. Repozytorium jest **prywatne**, dlatego wydania są widoczne tylko dla osób z dostępem.

**Status: kompilacje rozwojowe, a nie certyfikowane wydania produkcyjne.** Korzystaj wyłącznie z kopii danych testowych. Aplikacje nie szyfrują jeszcze całego dysku systemowego ani całego telefonu.

![KRYPTA — interfejs Windows/Linux](assets/matrix-ui.png)

## Możliwości KRYPTA

| Funkcja | Windows | Linux | Android |
|---|:---:|:---:|:---:|
| Graficzny interfejs | ✅ | ✅ | ✅ |
| Szyfrowanie i odszyfrowywanie wybranych plików | ✅ | ✅ | ✅ |
| AES-256-GCM z uwierzytelnieniem integralności | ✅ | ✅ | ✅ |
| Hasło i Argon2id | ✅ | ✅ | — |
| Android Keystore i uwierzytelnienie urządzenia | — | — | ✅ |
| Własny silnik zaszyfrowanych woluminów PVIMG/1 | W kodzie | W kodzie | — |
| Potwierdzone montowanie zaszyfrowanego katalogu przez FUSE | — | ✅ osobne narzędzie | — |
| Transparentne szyfrowanie całego urządzenia | ❌ | ❌ | ❌ |
| Sprzętowy limit prób krótkiego PIN-u | ❌ | ❌ | ❌ |
| Zweryfikowane przenośne odzyskiwanie kluczy | ❌ | ❌ | ❌ |

### Windows i Linux — File Vault

Szyfrowanie wybranych plików do formatu KRYPTA przy użyciu AES-256-GCM, losowego klucza danych, Argon2id i opcjonalnego pliku klucza. Dane pozostają lokalne; hasło nie jest przekazywane przez argumenty CLI. Przy pomocy graficznej aplikacji można wybrać plik i wykonać szyfrowanie lub odszyfrowanie.

### Android — File Vault

KRYPTA-MOBILE/1 pozwala zaszyfrować i odszyfrować wybrany dokument z użyciem AES-256-GCM i urządzeniowego Android Keystore. Aplikacja nie ma uprawnień do zastąpienia szyfrowania całej pamięci telefonu. **Android i desktop mają obecnie różne formaty plików.**

### Encrypted Volume Engine — Linux i Windows

KRYPTA-PVIMG/1 ma własny uwierzytelniony wielopoziomowy indeks, szyfrowanie sektorów i transakcje copy-on-write. W Linux pomyślnie zweryfikowano **rzeczywiste montowanie FUSE** i operacje na pliku 610 KiB. Obecny zaszyfrowany katalog PFS/1 jest płaski i obsługuje do 128 plików, każdy do 960 KiB. **1 GiB logicznej przestrzeni adresowej silnika nie jest gwarancją 1 GiB użytecznej pojemności.**

[Stan funkcji i bezpieczeństwa](docs/SECURITY_STATUS.md) · [Linux FUSE — dowody](docs/PVIMG_LINUX_FUSE.md) · [Plan ukończenia wersji 1.0](docs/PRODUCT_ACCEPTANCE.md)

## Instalowanie i bezpieczeństwo pobierania

**Windows:** pobierz plik EXE i sprawdź jego SHA-256. EXE nie ma produkcyjnego podpisu wydawcy, więc Windows może ostrzegać. Nie obchodź ostrzeżeń systemu bez sprawdzenia pochodzenia pliku.

**Linux:** pobierz plik KRYPTA-Linux-x64. Wymaga kompatybilnego środowiska graficznego oraz bibliotek Tk. Uruchom:

~~~bash
chmod +x KRYPTA-Linux-x64
./KRYPTA-Linux-x64
~~~

**Android:** pobierz APK debug. Jego podpis **nie jest stabilnym podpisem produkcyjnym**. Nowy APK może wymagać ponownego zainstalowania, a odinstalowanie, reset Android Keystore lub utrata urządzenia mogą **nieodwracalnie uniemożliwić odszyfrowanie** danych. Nie używaj go do jedynych kopii dokumentów.

## Odblokowanie zaszyfrowanych woluminów — prace nad kluczami

Własny silnik woluminów otrzymał osobny format `KRYPTA-PVKEY/1`: długie hasło (Argon2id) i **niezależny 256-bitowy klucz odzyskiwania**. Obsługiwane jest również testowe montowanie FUSE z kluczem odblokowanym przez hasło zamiast surowego klucza. Funkcja jest na razie dostępna w narzędziach źródłowych, **nie jako ukończona funkcja pobieranego EXE lub APK**. Krótki PIN bez prawdziwej sprzętowej kontroli prób nie daje odporności na odgadywanie. [Dokumentacja](docs/PVKEY_PASSWORD_RECOVERY.md).

## Docelowe funkcje produktu

1. Pełne, automatyczne szyfrowanie woluminów Windows i Linux.
2. Obsługa dysków USB, SSD i HDD oraz bezpieczny proces odzyskiwania.
3. Sprzętowo chronione klucze i krótkie PIN-y z rzeczywistą blokadą prób odgadywania.
4. Ochrona rozruchu i dysków systemowych po weryfikacji na odizolowanym sprzęcie.
5. Bezpieczna integracja z Androidem w zakresie, na jaki pozwalają uprawnienia systemu.
6. Niezależny audyt, testy awarii i porównanie z uznanymi rozwiązaniami.

**Celem jest najwyższa mierzalna jakość zabezpieczeń.** Nie deklarujemy przewagi nad każdym innym systemem bez testów porównawczych, audytu i dowodów.

## Dokumentacja i rozwój

[Architektura](docs/ARCHITECTURE.md) · [Wymagania wersji 1.0](docs/PRODUCT_ACCEPTANCE.md) · [Instrukcja budowania](docs/BUILD_AND_RELEASE.md) · [Bezpieczeństwo](SECURITY.md) · [Testy i kompilacje](https://github.com/promirmir/KRYPTA/actions)

---

### English

**KRYPTA** is an independent encryption project for Windows, Linux and Android. **[Download the development EXE, Linux executable and Android APK from GitHub Releases](https://github.com/promirmir/KRYPTA/releases).** Selected-file encryption works on all three platforms; the authenticated encrypted-volume engine and Linux FUSE integration are under development. These versions do **not** protect full system disks/phones and do not have production key recovery, independent audit or guaranteed secure short-PIN protection. Use disposable test data only. Downloads are private to repository collaborators.
