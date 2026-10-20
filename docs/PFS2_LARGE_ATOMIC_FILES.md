# KRYPTA-PFS/2 — atomowe pliki do 32 MiB na PVIMG/1

**Rzeczywisty zakres:** osobny wersjonowany system plików dla zwykłych zaszyfrowanych obrazów testowych `.kpv`, połączony z adapterem FUSE w Linux. Nie jest szyfrowaniem całego dysku systemowego, produkcyjnym urządzeniem blokowym ani sterownikiem Windows.

## Co zostało wdrożone

- Nowy identyfikator `KRYPTA-PFS/2`, niezależny od `KRYPTA-PFS/1`. Stare obrazy PFS/1 pozostają otwierane w starym formacie — **nie ma niejawnej migracji**.
- **Maksymalnie 32 MiB na jeden plik** przy płaskim katalogu maksymalnie 128 plików. Maksymalny rozmiar zaszyfrowanej metadanej katalogowej wynosi 64 KiB; wiele dużych plików może zapełnić ją wcześniej.
- Własny silnik PVIMG/1 przechowuje dane w uwierzytelnionym indeksie copy-on-write, a katalog PFS/2 obejmuje nazwę, rozmiar, przypisane sektory i SHA-256 całego pliku. Sektory `null` oznaczają logiczne zera bez zajmowania miejsca w szyfrogramie.
- Operacje: tworzenie, nadpisanie, odczyt zakresu, zapis zakresu, rozszerzenie i skrócenie pliku, zmiana nazwy, usunięcie i pełna weryfikacja wszystkich aktualnie widocznych plików.
- Odmiana transakcji `PagedResearchVolume.write_many_atomic_large()` dopuszcza do 8208 sektorów danych i katalogu, zachowując jeden końcowy, uwierzytelniony rekord zatwierdzenia.
- **Atomowy zapis dużego pliku:** nowe zaszyfrowane rekordy są dopisywane, lecz nieosiągalne poprzez stary indeks do momentu zapisania końcowego commitu. Gdy operacja zostanie przerwana przed zatwierdzeniem, wolumin po ponownym otwarciu zachowuje **poprzedni** podpisany stan katalogu i poprzedni zewnętrzny `receipt`. Nie publikuje się częściowo zapisanej wersji pliku.
- W czasie małych zmian zapisuje się wyłącznie zmienione sektory, nie całą zawartość pliku. Przy sprawdzaniu integralności całość danych może jednak wymagać odczytu.
- W Linux dotychczasowy adapter FUSE wybiera PFS/2 według **uwierzytelnionego nagłówka** zaszyfrowanego obrazu. PFS/1 nadal działa.

## Ograniczenia bezpieczeństwa

**1 GiB adresowanej przestrzeni logicznej PVIMG/1 nie oznacza 1 GiB użytkowej pojemności.** Obecny plik dziennika ma sztywny limit 512 MiB, a rozmiar zapisu wzrasta z liczbą starych wersji zaszyfrowanych bloków. Podkatalogi, ACL, blokady i poprawne zachowanie wszystkich operacji POSIX pozostają niewdrożone.

Zapisy do 32 MiB i duże, synchronizowane transakcje mogą zajmować istotny czas i zwiększać pamięć procesu. Nie ma testów rzeczywistego odłączenia zasilania w połowie zapisu ani niezależnego audytu. Dotychczasowe testy symulują awarię zapisu przed końcowym commitem i sprawdzają otwarcie z **tym samym zewnętrznym receipt**.

Przechowywanie najnowszego `receipt` w zaufanym miejscu poza plikiem nadal jest wymagane, jeśli system ma rozpoznawać cofnięcie całego obrazu. Nie ma sprzętowego ogranicznika prób PIN, bezpiecznego wymazywania przestarzałych szyfrogramów ani kompletnego odzyskiwania kluczy.

## Dowody

`tests/test_paged_fs2.py`: plik 3 MiB zapisany w jednej transakcji, odczyt zakresowy, zmiana trzech bajtów bez przepisywania megabajtów, rzadki plik 32 MiB, rozmiar maksymalny, odszyfrowanie po ponownym uruchomieniu, stara wersja PFS/1, błąd klucza, niedopuszczalne współdzielenie sektorów, odmowa niewłaściwych operacji i **odtwarzanie po symulowanym przerwaniu przed commitem**.

`tools/test_kernel_paged_fuse.py`: faktyczny test FUSE w jednorazowej maszynie Linux, zapis i odczyt pliku 1,4 MB, mały zapis w środku, rename, append, unlink, odmontowanie, ponowne otwarcie. Wyłącznie jawny **PASS** w logu potwierdza prawdziwy test jądra; infrastrukturalny SKIP nie jest uznawany za wykonanie testu.

## Co dalej

Potrzebne są: wydajna hierarchiczna struktura katalogów, dziennikowanie metadanych i kompakcja, testy na rzeczywistym sprzęcie z odłączaniem zasilania, zaufany sprzętowy anchor i klucze odzyskiwania, pełna semantyka POSIX, następnie integracja Windows. Żadnego użycia na fizycznych dyskach ani dla jedynej kopii wrażliwych danych.
