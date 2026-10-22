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
