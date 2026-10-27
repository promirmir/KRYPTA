# KRYPTA — fizyczne USB / SSD / HDD

**Cel ukończenia:** automatyczne, transparentne szyfrowanie całego wybranego
dysku lub partycji, z odzyskiwaniem po utracie zasilania, na Windows i Linux.
Plik `.kpv` na pamięci USB nie oznacza zaszyfrowania całego urządzenia.

## Nowy etap: bezpieczna identyfikacja prawdziwego dysku

`krypta.physical_disks` odpytuje systemowe metadane (Windows: `Get-Disk`;
Linux: `lsblk`): rzeczywista nazwa, pojemność, rodzaj połączenia, wykryte
partycje/montowania, sygnał dysku rozruchowego/systemowego, stan odczytu.
Interfejs Volume Lab wyświetla to jako **Dyski fizyczne (R/O)**.

**To nie jest szyfrowanie fizycznego dysku.** Moduł nie otwiera dysków,
nie odmontowuje, nie formatuje, nie zapisuje. Każda pozycja raportuje
`write_authorized: false`. Przy niepełnych informacjach status pozostaje
niepewny, nie „bezpieczny”.

## Etap read-only: pełna zaszyfrowana kopia USB (development)

Polecenie Linux: `python -m krypta physical-backup /dev/sdX /sciezka/backup.krypta --keyfile /osobny/sekret`.
Przed użyciem utwórz osobny klucz `python -m krypta gen-keyfile /osobny/sekret`;
CLI prosi o hasło bez umieszczania go w historii powłoki. Urządzenie musi
być całym, niemontowanym, niesystemowym dyskiem USB. Odczyt korzysta wyłącznie
z `O_RDONLY`; żaden sektor źródłowy nie jest zapisywany. Program zapisuje
**nowy plik** `.krypta` na innym dysku za pomocą istniejącego
KRYPTA-FILE/2 (Argon2id + AES-256-GCM, uwierzytelniony znacznik końca);
wymaga dodatkowego pliku klucza. Awaria odczytu, zmiana urządzenia albo
montowanie przed zakończeniem powoduje odmowę opublikowania backupu.

**Dwufazowa publikacja archiwum (P0):** zaszyfrowane bajty trafiają
najpierw do losowo nazwanego pliku tymczasowego w docelowym katalogu,
nie do widocznej ścieżki `backup.krypta`. Następuje pełne, uwierzytelnione
ponowne odczytanie AES-GCM i porównanie SHA-256 oraz długości plaintextu
ze strumieniem wejściowym — bez wypisywania plaintextu. Dopiero wtedy
system publikuje wynik przez atomowe dowiązanie `os.link` bez nadpisania
cudzego pliku. W Linuksie synchronizowany jest również katalog docelowy.
Niepowodzenie weryfikacji usuwa tymczasowy plik i **nie publikuje** backupu.
Jeżeli zawiedzie synchronizacja katalogu już po utworzeniu dowiązania,
wynik zostaje oznaczony jako niepewny i wymaga niezależnej weryfikacji.
Nie stanowi to pełnej ochrony przed złośliwym procesem posiadającym te
same uprawnienia ani gwarancji trwałości po rzeczywistej utracie zasilania.

Przywrócenie do **zwykłego pliku** `.img` można testować przez
`python -m krypta decrypt backup.krypta restored.img --keyfile /osobny/sekret`.
Nie ma i nie wolno używać komendy przywracania na dysk fizyczny.
**Wynik to nie migawka atomowa**: inny proces może zmienić urządzenie podczas
odczytu mimo braku mountpointu. Weryfikacja i niezależne odtworzenie są
obowiązkowe; nie usuwać oryginału. Nie testowano na fizycznym USB ani
nie przeprowadzono niezależnego audytu. To nie jest szyfrowanie dysku w locie.

## Przywracanie kopii USB do bezpiecznego pliku .img (Windows / Linux)

`python -m krypta physical-restore-image backup.krypta fresh.img --keyfile independent.secret`

Nowy moduł `krypta.physical_restore` udostępnia odrębny krok ćwiczenia odzyskiwania: pełna weryfikacja AEAD przed odszyfrowaniem, kontrolowane odszyfrowanie do ukrytej losowej ścieżki, niezależne sprawdzenie bajtów odtworzonego pliku SHA-256 i długością, atomowa publikacja nowej ścieżki bez nadpisania oraz sprzątanie własnego staging. Plik wynikowy `.img` zawiera **jawne dane**. Odmowa zapisu na urządzenia fizyczne, do katalogów jądra, na symboliczne linki i do istniejących plików. Nie jest obsługiwany zapis wynikowego obrazu na USB/SSD/HDD, nie gwarantuje spójności odczytu pierwotnego USB, odporność przed atakami samego konta użytkownika wymaga dalszej oceny. Wymaga pozytywnych CI i oddzielnych testów odtworzenia na docelowych systemach.

## Linux: zapisy blokowe przez wyłącznie testowy /dev/loopN (P0)

Moduł `research/linux_loop_aead.py` umożliwia otwarcie **już istniejącego**
zaszyfrowanego obrazu `.kdevtest` przez urządzenie `/dev/loopN` połączone
przez jądro Linuksa dokładnie z tym plikiem. Wykorzystuje rzeczywiste
`pread/pwrite` w sektorach 4 KiB, `fsync`, istniejące COW AES-256-GCM v2
i obowiązkowy zewnętrzny **aktualny** receipt. Nie tworzy dysku, nie montuje,
nie partycjonuje ani nie inicjalizuje żadnego urządzenia.

Backend weryfikuje przez `LOOP_GET_STATUS64` numer pętli, inode i urządzenie
pliku backing, zero offsetu i brak obcięcia, spójność `BLKGETSIZE64`,
uprawnienia i własność pliku (Linux), brak hardlinków, niezmienność tożsamości
przed każdym I/O. Otwiera /dev/loopN z `O_EXCL|O_NOFOLLOW`, odmawia wszystkich
`/dev/sd*`, `/dev/nvme*`, partycji i innych ścieżek. Błędy lub krótkie
transfery blokują dalsze operacje do niezależnej analizy receipt.

Do zademonstrowania na prawdziwym kernel-loop potrzebne są osobne testy na
izolowanej maszynie (wymaga losetup i stosownych uprawnień); CI obecnie
używa symulacji urządzenia blokowego i rzeczywistych zaszyfrowanych plików.
`/dev/loopN` odwołuje się do pliku dyskowego i **nie oznacza obsługi
fizycznego USB, SSD ani HDD**. Kod nie jest udostępniony jako komenda
formatowania, nie jest jeszcze produkcyjny. Ostateczny format, sterowniki,
współbieżność i realne awarie zasilania pozostają niewdrożone.

## Wdrożenie interfejsu użytkownika i testów gotowego programu

Desktop Linux: dedykowane okno w **Drive Shield**, wybór urządzenia z listy
niemontowanych źródeł USB, pliku `.krypta`, oddzielnego keyfile i hasła
z potwierdzeniem. Operacja wymaga świadomej zgody i jest wykonywana poza
wątkiem Tk; nie ma żadnego wywołania zapisu na urządzeniu źródłowym.
Próba zamknięcia okna/programu podczas pracy jest odrzucana. Windows EXE
**nie** pokazuje tej operacji — nadal tylko identyfikuje dyski.
Android APK działa wyłącznie na wybranych plikach.

Ważne dowody: test gotowego **Windows EXE i Linux ELF**
`--usb-backup-self-test` tworzy *prawdziwy zaszyfrowany archiwum* z
syntetycznego adaptera i weryfikuje pełne odtworzenie do pliku. Test nie
korzysta z urządzenia fizycznego. Oddzielne CI
`kernel-loop-real.yml` rzeczywiście przyłącza prywatny plik .kdevtest do
`/dev/loopN`, wykonuje zaszyfrowany zapis 4 KiB i odczyt przez jądro.
Jeśli runner nie obsługuje loop, test kończy się **niepowodzeniem**,
nie jest zaliczany przez symulację. Nie oznacza to testu na fizycznym USB.

## Blokery pełnego wsparcia fizycznych dysków

1. Nowy on-disk layout i niezawodny backend urządzeń, niezależny od
   obecnego append-only i 512-MiB limitu testowego PVIMG.
2. Własny adapter bezpiecznego montowania i zapisu na Windows/Linux,
   blokady konkurencyjnych zapisów, spójność, alignment, flush/FUA.
3. Testy na emulowanych blokowych urządzeniach (odłączenie kabla, brak
   zasilania, błędy zapisu, przerwane commit), recovery i zgodność między OS.
4. Niszcząca inicjalizacja tylko pustego/świadomie przeznaczonego nośnika
   po zweryfikowaniu tożsamości urządzenia, backupu, braku montowań oraz
   dwustopniowym potwierdzeniu; twardy zakaz dysku systemowego.
5. Dopiero po spełnieniu powyższych punktów oddzielne testy na
   fizycznym nośniku testowym. Dyski systemowe to osobny etap.

Projekt ma własny silnik, nie jest nakładką na BitLocker ani LUKS.
