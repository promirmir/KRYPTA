# KRYPTA-PFS/1 — szyfrowany system plików na PVIMG/1

**Stan techniczny:** zaimplementowana warstwa plików oraz adapter Linux FUSE dla odizolowanych, zwykłych obrazów `.kpv`. Nie jest to ukończone szyfrowanie systemowego dysku Windows/Linux ani wydanie bezpieczne dla jedynej kopii ważnych danych.

## Rzeczywiste możliwości

- Samodzielny silnik PVIMG/1 chroni dane i metadane katalogu; FUSE służy tylko do połączenia z jądrem Linux, nie deleguje szyfrowania do LUKS.
- Oddzielny format `KRYPTA-PFS/1`, niekompatybilny z `KRYPTA-FS/0`, z katalogiem zajmującym 16 szyfrowanych sektorów i do **128 plików**.
- **960 KiB maksymalnej wielkości pojedynczego pliku**. Ograniczenie wynika z wymaganej atomowości: do 240 sektorów pliku plus 16 sektorów katalogu mieszczących się w jednej transakcji PVIMG (maks. 256). Przestrzeń adresowa silnika wynosi 1 GiB logicznie, ale zapis jest ograniczony również do 512 MiB pliku dziennika wraz z narzutami. **Nie twierdzimy, że wolumin ma 1 GiB użytecznej pojemności.**
- Katalog płaski, bez podkatalogów; nazwy Unicode NFC i ochronna walidacja niedozwolonych nazw.
- Zapis, częściowe nadpisanie, dopisanie, zmiana nazwy, usunięcie, odczyt i weryfikacja integralności. Modyfikacja pojedynczego pliku i metadanych następuje w jednej zatwierdzanej transakcji. Przerwanie zapisu odrzuca dalsze operacje do ponownego otwarcia i odzyskania poprzedniego zatwierdzonego stanu.
- Oddzielny `research/linux_mount_paged.py` montuje tylko istniejący, poprawnie sformatowany plik `.kpv`. Wymaga zwykłego użytkownika (zakaz root), pustego prywatnego katalogu (0700), losowego 32-bajtowego klucza dostarczonego anonimowym potokiem, **zewnętrznego** potwierdzenia stanu (`--expected-receipt`) i świadomej flagi uruchomienia.
- Operacje niemożliwe do poprawnej realizacji (ACL, stałe atrybuty czasu, chmod/chown, katalogi, symlinki, hard linki) są jawnie odrzucane. Operacje na otwartych plikach nie implementują jeszcze wszystkich reguł POSIX.
- Katalog i pliki są niewidoczne w postaci jawnej w obrazie hosta, ale nazwa KRYPTA, rozmiar obrazu i wzorzec przyrostu dziennika są jawne.

## Nowszy, oddzielny format PFS/2

Zaimplementowano osobny zaszyfrowany katalog `KRYPTA-PFS/2` obsługujący **pliki do 32 MiB** oraz jednorazowe uwierzytelnione zatwierdzanie danych i katalogu. Adapter Linux FUSE rozpoznaje wersję formatu po uwierzytelnionym nagłówku. Wszystkie limity PFS/1 opisane poniżej pozostają prawdziwe dla starych obrazów; nie dokonujemy ich automatycznego podnoszenia do nowego formatu. [Szczegóły PFS/2](PFS2_LARGE_ATOMIC_FILES.md).

## Usprawniony zapis i odzyskiwanie żywych plików

- Przy zamianie zawartości pliku `PagedFileSystem.write_file(..., replace=True)` najpierw uwierzytelnia istniejące dane i SHA-256, zachowuje niezmienione odnośniki sektorów, a do jednej transakcji PVIMG zapisuje wyłącznie **zmienione sektory** wraz z katalogiem. Zapisy identycznych danych nie zwiększają licznika transakcji.
- Nowe `PagedFileSystem.export_live_files(new_path)` tworzy **oddzielny**, świeżo szyfrowany obraz. Kopiuje tylko pliki nadal widoczne w katalogu, sprawdza dane przed kopiowaniem i weryfikuje wszystkie pliki w obrazie wynikowym. Usunięte pliki oraz porzucone sektory nie są przenoszone do nowego obrazu.
- Źródło pozostaje niezmienione. Plik wyjściowy nie może istnieć wcześniej. Przy wykrytym błędzie kopiowania usuwany jest tylko nowo utworzony plik, o ile nie został podmieniony pod tą ścieżką.
- Nowy obraz ma **odrębny identyfikator, licznik i receipt**. Zewnętrzne zaufane potwierdzenie aktualnego stanu należy obsłużyć osobno; stary receipt nie autoryzuje nowego obrazu. Nie jest to bezpieczne wymazywanie starego nośnika ani gwarancja przetrwania fizycznej utraty zasilania.

Dowody: `tests/test_paged_incremental.py`, `tests/test_pfs_live_export.py` oraz test prawdziwego montowania FUSE z trzybajtową modyfikacją pliku 610 KiB.

## Bezpieczeństwo i ograniczenia

- **Brak zaufanej ochrony przed rollback.** Sam poprawny HMAC dawnej wersji obrazu nie wystarcza; wymagany jest najnowszy zaufany receipt przechowywany niezależnie.
- **Brak bezpiecznego wymazywania**: usunięcie pliku usuwa wpis katalogowy, nie dawny szyfrogram ze wszystkich historycznych rekordów PVIMG. Eksport kompaktujący na poziomie bloków może zachowywać osierocone sektory.
- Nieprzetestowana odporność na rzeczywiste zaniki zasilania, przywracanie TPM, błędy sprzętowe, root-malware i ataki na niezależnie nieaudytowaną konstrukcję HORIZON/0.
- Obsługa FUSE jest synchroniczna i jednowątkowa. Zmiana pliku wymaga obecnie odczytu i weryfikacji całej jego zawartości, ale na dysku ponownie szyfrowane są **tylko zmienione sektory** i 16 sektorów katalogu. Nadal nie zapewnia to wydajności produkcyjnego systemu plików.
- **Nie używać na fizycznych dyskach, partycjach systemowych ani z jedyną kopią danych.** System nie jest gotowy do produkcyjnego użycia.
- Format PVIMG-PFS/1 ma odrębny nagłówek. Ani starsze pliki `.kvi`, ani pliki `.kry` nie są automatycznie konwertowane.

## Dowody i testowanie

Testy jednostkowe: `tests/test_paged_fs_fuse.py` oraz wcześniejsze testy PVIMG. Sprawdzają m.in. pliki przekraczające całkowitą pojemność starszego VIMG, montowanie przez symulowane operacje FUSE, częściowe zapisy, odczyty, niepoprawne uchwyty, uprawnienia, atomowość przy symulowanej awarii i zewnętrzne potwierdzenie stanu.

Test montowania z prawdziwym jądrem: `tools/test_kernel_paged_fuse.py`. GitHub Actions uruchamia proces FUSE na Linux, tworzy testowy plik 610 KiB, odczytuje, zmienia nazwę, dopisuje dane, usuwa, odmontowuje i otwiera ponownie zaszyfrowany obraz. **Jeżeli runner nie oferuje urządzenia FUSE, zgłaszany jest jawny SKIP, nie PASS.** Właściwym dowodem montowania jest tylko rzeczywisty wynik `PASS` w logu.

## Warunki dalszych prac

W następnej fazie konieczne jest rozszerzenie **rozmiaru plików ponad 960 KiB** i ograniczenie potrzeby odczytu całego pliku podczas drobnego zapisu, wdrożenie trwałej struktury katalogów, poprawnej semantyki POSIX, ograniczonej pamięci i pełnego odtwarzania po awarii. Dopiero wtedy uzasadniona będzie warstwa stabilnego montowania dysków wymiennych i prace nad Windows.
