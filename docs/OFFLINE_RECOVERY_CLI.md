# KRYPTA / AWARYJNE ODZYSKIWANIE PFS/2 BEZ GUI

**Status: tylko wersja badawcza.** Ta procedura działa niezależnie od
graficznej aplikacji Windows/Linux, lecz **wymaga Pythona 3.10+ i
zainstalowanych zależności projektu**. Nie jest samodzielnym
instalatorem, narzędziem do odzyskania całego dysku systemowego ani
aplikacją Android. Obsługuje wyłącznie płaskie obrazy plikowe PVIMG/1
z systemem PFS/2, stworzone w testowym Volume Lab.

## Przed rozpoczęciem

Przygotuj **kopię** zaszyfrowanego obrazu \`data.kpv\`, pasujący plik
\`keys.pvkey\`, niezależny **32-bajtowy sekret**
\`independent.recovery\` oraz aktualny 64-znakowy
**zewnętrzny zaufany** \`receipt\`. Jeśli ostatniego receipt nie
masz, nie akceptuj automatycznie wartości z samego obrazu —
zniknęłaby ochrona przed cofnięciem stanu (rollback).

Nie umieszczaj pliku recovery w repozytorium, usługach publicznych,
w komunikatorze lub obok udostępnianego ciphertextu. Operuj bez
administratora i na kopiach danych testowych. Sekret recovery daje
uprawnienie do odszyfrowania danych bez hasła użytkownika.

Po pobraniu zaufanej kopii źródła:

~~~sh
python -m pip install -e '.[test]'
~~~

## 1. Sprawdzenie obrazu i wypisanie zawartości

~~~sh
python -m research.paged_key_cli list-files \
  --image data.kpv \
  --envelope keys.pvkey \
  --recovery independent.recovery \
  --expected-receipt 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --acknowledge-test-only
~~~

W powyższym przykładzie **64-cyfrowy receipt jest fikcyjny** —
podmień go na własny z bezpiecznej kopii. Funkcja:
- odblokowuje obraz wyłącznie niezależnym kluczem recovery,
- sprawdza prawdziwą tożsamość obrazu i jego latest receipt,
- uwierzytelnia katalog i pełne dane wszystkich aktualnych plików,
- wypisuje dokładne nazwy i rozmiary, ale nie tworzy żadnego plaintextu,
- otwiera obraz w trybie **read-only**, bez przycinania fragmentów po awarii.

## 2. Eksport pojedynczego odzyskanego pliku

~~~sh
python -m research.paged_key_cli export-file \
  --image data.kpv \
  --envelope keys.pvkey \
  --recovery independent.recovery \
  --expected-receipt 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --name "example.txt" \
  --output "restored-copy.txt" \
  --acknowledge-test-only
~~~

Zamiast \`example.txt\` wpisz nazwę z wyniku \`list-files\`.
**Output jest JAWNY**, nigdy nie zostanie nadpisany, jeśli już istnieje.
Nie wydobywaj go na współdzielony nośnik i nie otwieraj nieznanych
plików wykonawczych. W razie błędnego receipt, klucza,
uszkodzonego szyfrogramu albo nazwy pliku operacja odmówi wydania
plaintextu. Zapis wyniku używa tworzenia wyłącznego (O_EXCL)
i bezpiecznego usuwania tylko własnego pliku po nieudanym zapisie.

## 3. Co jest, a czego nie ma

Polecenie \`recover-password\` tworzy kolejny envelope po użyciu
klucza odzyskiwania, **ale nie unieważnia** starego hasła ani
starego envelope. Rotacja wymaga osobnego, zweryfikowanego
przeniesienia danych do NOWEGO obrazu i klucza DEK.

Polecenie \`verify\` także otwiera istniejący obraz w trybie
**read-only**. Żadne z nowych poleceń nie próbuje formatować,
montować czy zapisywać partycji i dysków. Procedura odzyskiwania
jest na razie zależna od dostępności kompatybilnego kodu źródłowego
oraz bibliotek Python — to nadal nie jest niezależne, archiwalne
narzędzie odzyskania na nowej maszynie i wymaga dalszej weryfikacji.

### Testy

\`tests/test_offline_recovery_cli.py\` obejmuje odzyskiwanie za pomocą
sekretu recovery bez hasła, błędny receipt, uszkodzenie szyfrogramu,
zakaz nadpisywania, brak uprawnienia bez \`--acknowledge-test-only\` i
zachowanie niezatwierdzonego ogona logu w trybie read-only.
\`tests/test_volume_lab.py\` kontroluje po utworzeniu woluminu
ponowne odblokowanie **dwoma niezależnymi metodami** i sprzątanie
nowych plików przy błędach. Pełne testy i sprawdzenie na docelowych
systemach pozostają wymagane do wydania.
