# KRYPTA-VIMG/0 — pierwszy obraz własnego woluminu (research only)

**Stan: demonstrator silnika, nie gotowy produkt do ochrony danych.** Komponent jest odrębny od BitLockera, LUKS i VeraCrypt. Nie montuje woluminów i nie obsługuje fizycznych dysków. Wymaga od wywołującego niezależnego losowego klucza 256-bitowego, nie PIN-u użytkownika. Nie zapisuje klucza do obrazu.

## Implementacja

- `research/volume_image.py` — zwykły plik testowy `.kvi` z limitem 64 MiB, 128 adresowalnych sektorów po 4096 B, z automatycznym szyfrowaniem danych w interfejsie zapisu sektorów.
- `research/horizon_lab.py` — eksperymentalne uwierzytelnione szyfrowanie pojedynczego sektora; AES-256-GCM + ChaCha20-Poly1305 z materiałem kluczowym rozdzielonym przez HKDF-SHA512.
- Format obrazu: jawny identyfikator `KRYPTA-VIMG/0`, losowy identyfikator 16 B, ramki zaszyfrowanych danych, ramki zatwierdzeń.
- Po każdym zapisie: tworzy nową zaszyfrowaną wersję bloku, fizycznie zatwierdza ją (fsync), następnie zatwierdza pełną mapę wersji z HMAC-SHA256 (drugi fsync). Metadane zawierają sekwencję, mapowanie numeru sektora, numer generacji, offset i skrót szyfrogramu.
- Odczyt: sprawdza integralność zatwierdzenia, poprawność mapy, wiązanie danych z adresem sektora i generacją, a następnie oba znaczniki AEAD. Błąd => wyjątek i brak danych jawnych.
- Symulacja przerwania zapisu/niepełnej końcowej ramki: odtwarza ostatni **kompletny uwierzytelniony commit**. Nie używa żadnych rzeczywistych urządzeń blokowych.
- Zewnętrzny oczekiwany numer sekwencji (*jeśli został zaufanie zachowany przez wywołującego*) potrafi wykryć cofnięcie stanu. **Dostarczona implementacja nie zabezpiecza tego numeru.**

## Ograniczenia i blokery

1. **To nie jest transparentny dysk montowany w Windows/Linux**; jest to warstwa odczytu/zapisu sektorów poprzez API i plik testowy. Windows wymaga później osobnej integracji sterownika; Linux osobnego urządzenia wirtualnego lub innej autorskiej warstwy montowania.
2. **Brak ochrony przed atakiem rollback:** napastnik może przywrócić starszy prawidłowy obraz wraz z metadanymi i w ten sposób cofnąć historię, jeśli nie ma niezależnego kotwiczenia aktualnego stanu. Nie należy nazywać tego rozwiązania rollback-safe.
3. **Brak uwierzytelniania PIN/TPM/SE ani odzyskiwania kluczy.** Przechowywanie klucza w programie lub razem z plikiem niweczy cel bezpieczeństwa.
4. **Brak weryfikacji sprzętowej** i ochrony dysku systemowego. Nie obsługuje Windows boot, Android FBE ani plików innych aplikacji.
5. **Brak gwarancji atomowości na wszystkich dyskach/systemach plików:** fsync+append nie jest gwarancją niezawodności przeciw awarii firmware, niestabilnym kontrolerom, nieuprawnionemu zapisowi, uszkodzeniu sektora metadanych albo manipulacji aktywnego root/administratora.
6. **Model single-writer:** POSIX advisory locking; na Windows blokada międzyprocesowa jeszcze niewdrożona. Nie wolno otwierać jednego obrazu równolegle w wielu procesach.
7. **Brak odzyskiwania po celowej modyfikacji ważnego commitu.** W razie naruszenia integralności proces przerywa odczyt zamiast cicho przejść na poprzedni commit. Utrata jedynej kopii może być trwała.
8. **Bezpieczeństwo samej konstrukcji HORIZON/0 pozostaje eksperymentalne.** Dwie warstwy szyfrowania nie dowodzą przewagi nad dojrzałym AEAD.
9. **Przewidywalny wzrost pliku obrazu:** append-only i ponawianie map, bez compaction, wear management, quota recovery i sprawdzonego garbage collection.
10. Przed użyciem produkcyjnym: korekta architektury metadanych, fuzzing parsera, fault injection fsync/partial write, cross-process isolation i obsługa platform, świadomy model recovery, analiza wycieków w pamięci oraz testy kopii zapasowych.

## Co dalej

- Wprowadzić właściwy menedżer transakcji COW z wieloma blokami na transakcję, sprzątaniem danych i pamięcią trwałą wersji.
- Zaprojektować *zewnętrzny* chroniony monotoniczny anchor anti-rollback.
- Model kluczy i odblokowania z PIN-em, w którym krótki PIN **nie jest jedynym sekretem**.
- Osobne prototypy wirtualnego urządzenia na Windows i Linux w odizolowanych maszynach wirtualnych.

**Przeznaczenie: wyłącznie syntetyczne dane testowe.**