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

## Bezpieczeństwo i ograniczenia

- **Brak zaufanej ochrony przed rollback.** Sam poprawny HMAC dawnej wersji obrazu nie wystarcza; wymagany jest najnowszy zaufany receipt przechowywany niezależnie.
- **Brak bezpiecznego wymazywania**: usunięcie pliku usuwa wpis katalogowy, nie dawny szyfrogram ze wszystkich historycznych rekordów PVIMG. Eksport kompaktujący na poziomie bloków może zachowywać osierocone sektory.
- Nieprzetestowana odporność na rzeczywiste zaniki zasilania, przywracanie TPM, błędy sprzętowe, root-malware i ataki na niezależnie nieaudytowaną konstrukcję HORIZON/0.
- Obsługa FUSE jest synchroniczna i jednowątkowa; każde nadpisanie pliku szyfruje go ponownie w całości. To ogranicza wydajność i liczbę trwałych zapisów.
- **Nie używać na fizycznych dyskach, partycjach systemowych ani z jedyną kopią danych.** System nie jest gotowy do produkcyjnego użycia.
- Format PVIMG-PFS/1 ma odrębny nagłówek. Ani starsze pliki `.kvi`, ani pliki `.kry` nie są automatycznie konwertowane.

## Dowody i testowanie

Testy jednostkowe: `tests/test_paged_fs_fuse.py` oraz wcześniejsze testy PVIMG. Sprawdzają m.in. pliki przekraczające całkowitą pojemność starszego VIMG, montowanie przez symulowane operacje FUSE, częściowe zapisy, odczyty, niepoprawne uchwyty, uprawnienia, atomowość przy symulowanej awarii i zewnętrzne potwierdzenie stanu.

Test montowania z prawdziwym jądrem: `tools/test_kernel_paged_fuse.py`. GitHub Actions uruchamia proces FUSE na Linux, tworzy testowy plik 610 KiB, odczytuje, zmienia nazwę, dopisuje dane, usuwa, odmontowuje i otwiera ponownie zaszyfrowany obraz. **Jeżeli runner nie oferuje urządzenia FUSE, zgłaszany jest jawny SKIP, nie PASS.** Właściwym dowodem montowania jest tylko rzeczywisty wynik `PASS` w logu.

## Warunki dalszych prac

W następnej fazie konieczne jest przetestowanie wielomegabajtowych plików bez przepisywania całej zawartości przy każdym `write`, trwałej struktury katalogów, poprawnej semantyki POSIX, ograniczonej pamięci i pełnego odtwarzania po awarii. Dopiero wtedy uzasadniona będzie warstwa stabilnego montowania dysków wymiennych i prace nad Windows.
