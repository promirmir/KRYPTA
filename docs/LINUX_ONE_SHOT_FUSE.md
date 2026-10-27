# KRYPTA — jednorazowy zapis FUSE PFS/2 (wyłącznie laboratorium)

Status: testy kodu, nie produkcyjny zaszyfrowany dysk. Własny format
KRYPTA-PVIMG/1 oraz PFS/2 pozostaje ograniczony do prywatnych plików
`.kpv`, bez fizycznego USB, SSD, HDD i bez sterownika dysku systemowego.

## Co zostało zaimplementowane

- `research.linux_fuse_staged_test.OneShotStagedFuseOps`: tylko jeden
  istniejący plik i maksymalnie jeden otwarty writer; nie obsługuje tworzenia,
  usuwania, zmiany nazw ani modyfikacji metadanych. Maksymalny bufor 4 MiB.
- Przed utworzeniem adaptera weryfikowany jest istniejący PFS/2 z
  **niezależnie zapieczętowanym** `.kpin`. Jego SHA-256 seal musi przyjść
  z innego, zaufanego kanału. Nie wolno traktować obecności pliku `.kpin`
  na tym samym dysku jako dowodu świeżości.
- Buforowane edycje odczytuje tylko writer; inne uchwyty widzą poprzedni
  uwierzytelniony stan. Zamknięcie bez `flush/fsync` anuluje zmiany.
- Przy pierwszej zatwierdzanej transakcji jeden COW commit jest wykonywany
  na już istniejącym obrazie; zwracany `observed_receipt_UNTRUSTED`
  jest **wyłącznie wynikiem obserwacji**, nie nowym punktem zaufania.
- Po próbie zatwierdzenia interfejs wymusza kwarantannę odczytów i zapisów
  do końca sesji. Utrata ACK/wyjątek nie uruchamia automatycznej akceptacji
  nowszego stanu; należy zachować poprzedni pin i zastosować niezależną
  procedurę odtwarzania. Brak następnego zapisu w tej sesji.
- Dostępna jest osobna opcja CLI `--one-shot-staged-write` wraz z
  `--test-root`, `--trusted-pin` i `--trusted-seal`.
  Zestaw nie łączy się z `--read-only` ani `--final-receipt-out`.
  Stary domyślny tryb FUSE oraz dotychczasowe formaty pozostają bez zmian.

## Warunki wejściowe

Do testów służy **tymczasowy katalog 0700 będący bezpośrednim dzieckiem**
`tempfile.gettempdir()`. W nim leży jedyny obraz `.kpv`; nie wolno
podawać dysku fizycznego ani przechowywać unikalnych danych. Pin i jego
seal muszą być niezależne od obrazu. Montowanie działa tylko w Linuksie,
w osobnym pustym katalogu 0700, bez konta root, `allow_other` i bez
dodatkowych wątków FUSE. Sposób przekazania hasła/klucza opiera się na
istniejących deskryptorach plików CLI, bez umieszczania sekretu w argumentach.

Schemat jawnego wywołania (metadane i deskryptory przygotowane niezależnie):

```text
python -m research.linux_mount_paged
  --image /tmp/<PRYWATNY-KATALOG>/only-test.kpv
  --mountpoint /tmp/<PRYWATNY-KATALOG>/mount
  --envelope /.../test.pvkey
  --password-fd <FD>
  --expected-receipt <TRUSTED-RECEIPT>
  --one-shot-staged-write
  --test-root /tmp/<PRYWATNY-KATALOG>
  --trusted-pin /.../other-directory/baseline.kpin
  --trusted-seal <EXTERNALLY-TRUSTED-SEAL>
  --accept-development-risk
```

Tego przykładu nie należy traktować jako instrukcji użycia na produkcyjnym
dysku. `<FD>` oznacza uprzednio otwarty deskryptor dostarczany przez
proces uruchamiający. Nie zapisujemy hasła w historii powłoki.

## Brakujące wymagania końcowe

Prawdziwy Linux FUSE write/read z wieloma plikami i równoczesnymi
writerami, niezawodne automatyczne potwierdzenie niezależnego stanu
na zewnętrznym monotonicznym nośniku, rzeczywiste awarie zasilania,
skalowanie przestrzeni, katalogi/uprawnienia, zgodność systemowa,
testy fizycznych dysków i niezależny audyt **nie są ukończone**.
Tego komponentu nie wolno eksponować jako gotowego systemu
transparentnego szyfrowania całego komputera.

Testy regresyjne: `tests/test_linux_fuse_staged_test.py`, uruchamiane
na gałęzi PR wraz z pełną macierzą Windows/Linux. Badania nie obejmują
fizycznych nośników użytkownika.
