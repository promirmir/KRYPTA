# KRYPTA — kompilacje i pobieranie

**Status: wewnętrzne kompilacje rozwojowe.** GitHub Actions tworzy wersje dla Windows x64, Linux x64 i Androida. Pliki nie są jeszcze audytowanymi ani podpisanymi produkcyjnie wydaniami.

## Pobieranie użytkownika

Główny adres: **[GitHub Releases](https://github.com/promirmir/KRYPTA/releases)**. Skonfigurowano workflow [publikacji trzech platform](../.github/workflows/publish-preview.yml), który po udanych testach i kompilacjach tworzy osobne, **prywatne prerelease** z plikami:

| System | Plik | Funkcja |
|---|---|---|
| Windows x64 | KRYPTA-Windows-x64.exe | Graficzne szyfrowanie/odszyfrowywanie wskazanych plików |
| Linux x64 | KRYPTA-Linux-x64 | Graficzne szyfrowanie/odszyfrowywanie wskazanych plików |
| Android | KRYPTA-Android-debug.apk | Szyfrowanie/odszyfrowywanie wskazanych plików za pomocą AES-256-GCM oraz Android Keystore |

Każdy plik wykonywalny ma odpowiadający mu załącznik SHA-256. Dla Androida dołączona jest lista żądanych uprawnień.

Workflow uruchamia się po zmianach kodu na gałęzi main lub jawnie ręcznie (Run workflow). Publikuje pliki tylko, gdy wszystkie trzy platformy i testy zakończą się powodzeniem. Każdy build ma oddzielny niezmienny tag wskazujący commit — nie nadpisuje poprzedniego wydania.

**Releases i pliki mogą pobierać tylko osoby z dostępem do prywatnego repozytorium.** Bez tego GitHub może wyświetlić 404.

## Co jest w aplikacjach

Windows i Linux: File Vault (.kry) obsługuje autoryzowane szyfrowanie pojedynczych plików, AES-256-GCM i wyprowadzanie klucza z hasła przez Argon2id. Kod PVIMG/PFS i Linux FUSE znajduje się w repozytorium jako osobne narzędzia; GUI nie szyfruje automatycznie dysku systemowego.

Android: KRYPTA-MOBILE/1 obsługuje wybrane pliki w Storage Access Framework, AES-256-GCM i klucz zawinięty przez Android Keystore. Jest to inny format niż desktop .kry. Zwykła aplikacja APK nie szyfruje całego telefonu.

## Krytyczne ostrzeżenia przed pobraniem

- Windows EXE nie ma podpisu wydawcy. Nie zalecamy obchodzenia ostrzeżeń SmartScreen.
- Linux ELF zależy od zgodnych bibliotek systemowych oraz Tk; uruchamiaj po sprawdzeniu SHA-256.
- Android APK jest podpisany **debugowo**, co nie zapewnia stałego klucza podpisywania wydań; aktualizacja kolejnej wersji może wymagać odinstalowania. Android Keystore jest związany z urządzeniem i aplikacją, a **utrata/odinstalowanie może trwale uniemożliwić odszyfrowanie** poprzednich plików.
- Nie istnieje produkcyjny system odzyskiwania kluczy, ochrona całych dysków ani udowodniony sprzętowo limit prób krótkiego PIN-u.
- Nie przeprowadzono niezależnego audytu bezpieczeństwa. Korzystaj wyłącznie z kopii danych do testowania.

## Dodatkowe tymczasowe artefakty Actions

Oddzielne workflow [desktop](../.github/workflows/build-desktop.yml) oraz [Android](../.github/workflows/build-android.yml) nadal przesyłają ZIP-y jako artefakty GitHub Actions. Te pliki zwykle wygasają po 14 dniach i nie są przeznaczone do prezentowania jako stałe linki pobierania.

## Kompilowanie lokalne

Python 3.10+ oraz pakiety projektu, PyInstaller 6.16:

~~~sh
python -m pip install -e '.[test]' pyinstaller==6.16.0
python -m pytest -q
python -m PyInstaller --noconfirm --clean --onefile --windowed --name KRYPTA krypta/desktop_entry.py
~~~

Windows: dist/KRYPTA.exe. Linux: dist/KRYPTA (budować na Linux). Android: JDK 17, Android SDK 35, Gradle 8.9 oraz komendy Gradle testDebugUnitTest, assembleDebug, lintDebug.

Produkcję 1.0 można zatwierdzić dopiero po spełnieniu [wymagań ukończenia](PRODUCT_ACCEPTANCE.md): odzyskiwanie, audyt, zgodność z systemami i sprzętem, bezpieczeństwo kluczy, aktualizacje oraz podpisane dystrybucje.
