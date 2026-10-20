# KRYPTA-FS/0 — własny zaszyfrowany katalog plików (research only)

**Zastosowanie: wyłącznie syntetyczne dane testowe.** Komponent jest autorski i niezależny od BitLockera, LUKS i VeraCrypt. Nie jest jeszcze montowanym systemem plików ani sterownikiem obsługującym fizyczne partycje.

## Co działa

- `research/fs_image.py` udostępnia `ResearchFileSystem` pracujący na zaszyfrowanych sektorach oryginalnego `KRYPTA-VIMG/0`.
- `format(volume)` formatuje **wyłącznie nowy testowy obraz w stanie genesis**. Odmawia ponownego formatowania obrazu zawierającego dane.
- `write_file(name, bytes)`, `read_file(name)`, `list_files()`, `stat()`, `rename_file()`, `append_file()`, `delete_file()` wykonują zwykłe operacje plikowe. **Każdy zapis podlega automatycznemu szyfrowaniu w silniku HORIZON**: użytkownik tej warstwy nie musi osobno wywoływać funkcji szyfrowania.
- Katalog jest sam zaszyfrowany. Zajmuje sektory logiczne 0–3, pozostałe 124 sektory przechowują małe pliki. Bieżący limit demonstratora to **48 nazw plików i 512 KiB logicznego obrazu**, maksymalnie ok. 496 KiB danych pojedynczego pliku bez pozostałych plików.
- Podczas tworzenia/nadpisywania pliku nowe wersje sektorów i metadane są zapisywane jedną transakcją `ResearchVolume.write_many()`. Zmiana nazwy i usunięcie wpisu również aktualizują katalog jednym rekordem zatwierdzenia.
- Katalog jest weryfikowany po odszyfrowaniu: poprawność wersji, limitów, nazwy, rozmiaru, skrótu treści, unikalności przydziału bloków i wyrównania danych. Wewnętrzne metadane są uwierzytelnione przez dwuwarstwowe AEAD i manifest VIMG.
- Nazwy plików używają UTF-8 NFC (w tym PL, RU, ZH), ale ograniczamy znaki nieprzenośne lub niebezpieczne w Windows/Linux. Brak katalogów podrzędnych, ACL i dowiązań.
- `research/fs_demo.py` tworzy losowe jednorazowe klucze i pliki wyłącznie w katalogu tymczasowym. Po teście usuwa syntetyczny obraz wraz z kluczem.

## Granice ochrony

**To nie jest jeszcze szyfrowanie transparentne na poziomie całego systemu operacyjnego.** Gdy zewnętrzna aplikacja korzysta z API `ResearchFileSystem`, dane są szyfrowane automatycznie. Zapis do dowolnego katalogu Windows/Linux nie przechodzi przez KRYPTA bez osobnej implementacji i integracji systemowej.

- Jednoczesne zmiany katalogu z dwóch obiektów `ResearchFileSystem` są wykrywane przez numer sekwencji i odrzucane. Nie ma jeszcze pełnego harmonogramowania wielu procesów.
- `delete_file()` **nie wymazuje kryptograficznie wcześniejszych rekordów** w append-only VIMG; do prawdziwej polityki usuwania/kompaktowania potrzebny jest oddzielny mechanizm.
- Nie ma trwałego niezależnego magazynu anti-rollback, sprzętowo ograniczonego PIN-u, odzyskiwania kluczy, boot protection, transakcji odpornych na awarię prawdziwego dysku, izolacji jądra ani certyfikacji.
- Nie jest możliwy bezpieczny zapis większych plików ani wielkiego katalogu: limity są celowo restrykcyjne, aby ułatwić badania.
- Kompozycja kryptograficzna HORIZON pozostaje eksperymentalna, bez udowodnionej przewagi nad standardową kryptografią.
- Poprawność testów aplikacyjnych nie daje gwarancji niezawodności firmware, rzeczywistego zasilania lub sprzętu.

## Kroki następne

Własny protokół operacji plikowych z atomowym katalogiem i blokami jest fundamentem pod FUSE/WinFsp *jako adapter wejścia/wyjścia*, nie jako cudzy silnik kryptograficzny. Następny etap wymaga obsługi plików o dowolnym rozmiarze, wielopoziomowego katalogu, trwałego indeksu, niezależnego zaufanego root commit, izolacji procesów i bezpiecznej kompakcji append-only. Dopiero później integracji ze sterownikami i rozruchem Windows/Linux.