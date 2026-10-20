# MODEL ZAGROŻEŃ — KRYPTA 0.4

## Zabezpieczamy

- Dane na wyłączonym komputerze, dane w pliku testowym, ewentualnie przyszłe woluminy.
- Integralność zaszyfrowanego pliku przed manipulacją, zamianą i ucięciem.
- W przyszłości: klucze przed brutalnym zgadywaniem PIN-ów w TPM/TEE.

## Atakujący

- Posiada skopiowany zaszyfrowany plik i nie zna hasła, ale może uruchamiać nieograniczoną liczbę prób lokalnie.
- Ma fizyczny dostęp do komputera/dysku wyłączonego albo nośnika USB.
- W bardziej wymagającym scenariuszu ma sprzęt do ataków na magistrale, pamięć i firmware.

## Zagrożenia niepowstrzymane w 0.4

- **Offline brute force PIN-u:** dla samego PIN-u 4-cyfrowego istnieje maksymalnie 10 000 prób; AES/Argon2id nie uniemożliwiają ich wykonania.
- Złośliwe oprogramowanie i keylogger działające, gdy odblokowany system przyjmuje PIN.
- Kradzież danych po odszyfrowaniu na podatnym systemie.
- Odzyskanie wcześniej istniejącej niezaszyfrowanej kopii, plików tymczasowych, pamięci RAM, plików wymiany, snapshotów, backupów.
- Atak na proces podczas działania, malware uruchomione z uprawnieniami administratora lub dostęp fizyczny do działającego komputera.
- Przejęcie klucza z pamięci procesu Python (w prototypie nie ma twardej gwarancji wymazywania sekretów).
- Ujawnienie rozmiaru pliku przez rozmiar szyfrogramu; utrata prawdopodobnej zaprzeczalności.
- Używanie keyfile przechowywanego razem z szyfrogramem.
- Podmiana kryptograficznego kodu lub pliku wykonywalnego (brak podpisów release).
- Zabezpieczenie przed rollbackiem licznika prób albo podmianą wersji pliku — nie ma mechanizmu sprzętowego.

## Bezpieczeństwo danych

- `encrypt` nie usuwa oryginału; `decrypt` zapisuje wynik tylko po pełnym sprawdzeniu integralności.
- Decrypt wytwarza plik tymczasowy (plaintext) na docelowym nośniku. Jeśli docelowy nośnik nie jest zaszyfrowany, pozostałości w warstwach pamięci masowej mogą pozostawać odzyskiwalne. Wersja 0.4 nieprzeznaczona do poufnych danych.
- Parametry szyfrowania i granice parsera są ustalone; metadane są uwierzytelnione.

## Kiedy test uznajemy za sukces

Poprawny PIN/hasło i klucz -> identyczny plik po odtworzeniu. Nieprawidłowy PIN, inny keyfile, zmiana segmentu, obcięcie, dodatkowe bajty -> błąd, brak opublikowanego pliku wynikowego. Nie oznacza to jeszcze ochrony przed aktywnym złośliwym oprogramowaniem.