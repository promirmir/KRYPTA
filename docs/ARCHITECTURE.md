# ARCHITEKTURA — KRYPTA

**Dokument nadrzędny:** [PROJECT_CHARTER.md](PROJECT_CHARTER.md).  
**Projektowane szyfrowanie:** [HORIZON_CRYPTO_RFC.md](HORIZON_CRYPTO_RFC.md).

## Zasada fundamentalna

**KRYPTA tworzy własny niezależny silnik szyfrowania woluminów i własną architekturę zarządzania kluczami. Nie jest adapterem ani nakładką na BitLocker, LUKS lub VeraCrypt.**

Istniejący w repozytorium `krypta/volume_status.py` może jedynie odczytywać stan innych systemów w celu diagnostyki/porównania. Nie jest i nie będzie silnikiem szyfrującym KRYPTA. Funkcja ta nie może prezentować ochrony BitLocker jako ochrony wykonanej przez KRYPTA.

## Model docelowy (niezaimplementowany)

```
Program / system plików
          |
Własny wirtualny wolumin KRYPTA
          |
Transakcyjna mapa COW + autentykowane metadane
          |
Autorskie uwierzytelniane rekordy bloków KRYPTA-HORIZON
          |
Fizyczny nośnik danych + niezależnie chroniony stan rollback
```

Transparentny zapis: przy każdej zwykłej operacji zapisu zmodyfikowany blok zostaje zaszyfrowany i uwierzytelniony bez dodatkowego klikania przez użytkownika. System odzyskiwania po przerwaniu zasilania nie może dopuścić do cichej utraty klucza, uszkodzenia głównej mapy bloków lub akceptacji niezweryfikowanego bloku.

## Klucze, PIN i brute force

- Wolumin: losowy klucz wysokiej entropii (≥256 bitów), niezależny od tekstu PIN-u.
- Uwierzytelnianie: PIN (dozwolony nawet 1-cyfrowy) lub hasło; sprzętowo zabezpieczony sekret / opcjonalny sprzętowy token oraz model odzyskiwania.
- Przy krótkim PIN-ie **bez** niezależnego sekretu i egzekwowanego poza nośnikiem limitu prób odporność na zgadywanie offline **nie jest możliwa**. Jeśli konfiguracja takiej ochrony nie zapewnia, interfejs musi jednoznacznie wskazać poziom ryzyka.
- TPM/TEE/secure element to możliwe korzenie zaufania do klucza, ale ograniczenia sprzętowe i utrata/zmiana sprzętu wymagają osobnej architektury backup i recovery.
- Przywrócenie starszej prawidłowej wersji zaszyfrowanego bloku nie zostanie wykryte przez sam AEAD — potrzebny niezależny zaufany stan wersji/metadanych.

## Windows — własny silnik

Docelowo: własny podpisany komponent dostępu do woluminu blokowego plus osobno przeanalizowany i przetestowany mechanizm ochrony rozruchu systemowego. Windows nie umożliwia zwykłej aplikacji w trybie użytkownika zamiany szyfrowania całego dysku C: w locie bez odpowiedniej integracji. Kod prototypowy ma działać najpierw wyłącznie na **plikowym obrazie woluminu testowego**. Brak produkcyjnego sterownika i szyfrowania przed rozruchem.

## Linux — własny silnik

Docelowo: własna implementacja adaptera urządzenia blokowego/montowania KRYPTA, nie konfigurator LUKS. Testy na obrazach w pamięci i zwykłych plikach, później tylko odizolowane maszyny wirtualne oraz testy awarii/zapisu. Nie instalować eksperymentalnego komponentu w rzeczywistym systemowym rootfs.

## Android — własna ochrona zgodna z ograniczeniami OS

APK może niezależnie chronić **pliki/kontenery kontrolowane przez aplikację** i korzystać ze sprzętowego przechowywania kluczy. Nie ma uprawnienia do transparentnej wymiany systemowego szyfrowania wszystkich plików innych aplikacji. Dla własnej ochrony całego telefonu konieczna jest uprzywilejowana integracja z obrazem/wersją Androida oraz sprzętem. Nie oznaczać APK jako pełnego FDE.

## Password Shield

Osobny sejf i reautoryzacja przed odsłonięciem sekretów. Aplikacje, którym już przekazano hasło, mogą je zachować w pamięci — brak gwarancji kontroli nad zewnętrznymi procesami.

## Autorskie szyfrowanie

`research/horizon_lab.py` to **odizolowany eksperyment** poddawany testom. Projekt bada autorską kompozycję dwóch mechanizmów AEAD, niezależne klucze dla poszczególnych zapisów i uwierzytelniane metadane. Nie oznacza to obecnie nowego, przełomowego szyfru ani udowodnionej przewagi nad standardowym AES-256. Docelowy format/algorytmy muszą umożliwić przyszłą migrację.

## Wydanie 1.0: cel a stan

Wydanie z rzeczywistą ochroną woluminu wymaga poprawnego uruchamiania, zamykania, odzyskiwania, zachowania po awarii, poprawnej obsługi kluczy i bezpieczeństwa danych. Testy i przeglądy są warunkiem oceny osiągniętego bezpieczeństwa, nie zamianą celu na cudzy produkt. Repozytorium pozostaje **PRIVATE** do osobnej decyzji właściciela.
