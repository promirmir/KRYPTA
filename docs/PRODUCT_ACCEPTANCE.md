# KRYPTA — kryteria ukończenia produktu

**Wiążący cel:** dostarczenie samodzielnego, użytkowego systemu szyfrowania — nie projektu prezentacyjnego. To dokument bramek akceptacyjnych dla wersji 1.0. Żaden moduł nie jest uznawany za ukończony na podstawie samej obecności kodu, GUI, kompilacji, testu jednostkowego ani deklaracji. Każdy pozytywny status wymaga odtwarzalnych testów na docelowej platformie i dowodów odzyskiwania danych.

**Stan bieżący: W TRAKCIE REALIZACJI.** Nie utożsamiać celu z istniejącą funkcjonalnością. Aktualne wyniki i zastrzeżenia znajdują się w [SECURITY_STATUS.md](SECURITY_STATUS.md). Jednoznaczny stan każdej głównej funkcji dla użytkownika: [FUNCTION_STATUS.md](FUNCTION_STATUS.md). Zaliczone testy dev nie zamykają automatycznie żadnej bramki wydania 1.0.

## P0 — bezpieczeństwo istniejących danych

- [ ] Żadna operacja tworzenia/montowania/migracji nie otwiera fizycznego nośnika bez jawnej autoryzacji i weryfikacji właściwego urządzenia.
- [ ] Każda potencjalnie niszcząca ścieżka wymaga kopii zapasowej, testu przywrócenia i jednoznacznego potwierdzenia użytkownika.
- [ ] Brak cichego nadpisania, utraty oryginału lub ujawnienia niezweryfikowanego plaintextu po błędzie.
- [ ] Weryfikacja odporności na wyłączenie zasilania i restart w każdym punkcie transakcji na odizolowanych maszynach i urządzeniach testowych.
- [ ] Procedury ratunkowe uruchamiane bez udziału aplikacji głównej; udokumentowany format i przywracanie.

### Postęp nad niezależnym odzyskiwaniem (2026-10-21)

W przygotowaniu znajduje się awaryjny CLI dla PFS/2 z podaniem niezależnego klucza recovery i zaufanego potwierdzenia stanu. Umożliwia sprawdzenie wszystkich plików i eksport jednej kopii plaintext bez GUI i bez nadpisywania. Tworzenie woluminu jest uznawane za udane dopiero po odblokowaniu **hasłem i kluczem odzyskiwania z nowo otwartego obrazu**. Są to funkcje badawcze i **nie zamykają kryteriów P0/P2**: potrzebne są dowody na drugim urządzeniu, z wyłączeniem zasilania, po awariach oraz z niezależną kopią narzędzia i dokumentacji. [Procedura](OFFLINE_RECOVERY_CLI.md).

## P1 — własny produkcyjny silnik zaszyfrowanego woluminu

- [ ] Ostateczna, wersjonowana specyfikacja on-disk z jawnie zdefiniowaną polityką kryptograficzną i niezależnym przeglądem.
- [ ] Skalowalny indeks COW i metadane: losowe zapisy, duże pliki, pełne nośniki, katalogi, prawa dostępu oraz odporność na manipulację.
- [ ] Atomowe wielosektorowe transakcje i przetestowane odzyskiwanie po realnej awarii; brak cichego zaakceptowania wadliwego stanu.
- [ ] Ograniczone zużycie pamięci i koszt pojedynczego zapisu niezależny od wielkości całej historii.
- [ ] Zarządzanie wolną przestrzenią, bezpieczna kompakcja/migracja oraz strategia nadpisywania i czyszczenia wycofanych danych.
- [ ] Ochrona przed rollback oparta na faktycznie zaufanym stanie poza kopiowalnym obrazem.
- [ ] Reprodukowalne testy integralności wszystkich danych, testy graniczne i fuzzing parserów.
- [ ] Kompatybilność odczytu, migracja oraz procedura odzyskania przy wymianie wersji algorytmu.

**Nie zamyka P1:** sukces jednego montowania FUSE, test 1-GiB adresowania logicznego, zielony pytest lub implementacja HORIZON/0 bez przeglądu.

## P2 — zarządzanie kluczami i uwierzytelnianie

- [ ] Osobny losowy klucz woluminu i klucze opakowujące; rozdzielenie domen/wersji/urządzeń.
- [ ] Sprzętowy, nieeksportowalny składnik sekretu tam, gdzie deklarowana jest sprzętowa ochrona.
- [ ] Krótki PIN: każdorazowa autoryzacja sprzętowa, prawdziwy limit prób, odporność na kopiowanie szyfrogramu i cofanie licznika prób.
- [ ] Odzyskiwanie po utracie urządzenia, wymianie płyty głównej/TPM, aktualizacji firmware i utracie kluczy — test z nowym sprzętem.
- [ ] Oddzielny model przenośności dysków USB i zarządzania zaufanymi urządzeniami.
- [ ] Klucze nie wyciekają przez argumenty poleceń, logi, telemetrykę ani publiczne repozytorium.
- [ ] Wyjaśnienie słabszego poziomu ochrony w konfiguracjach bez realnego sprzętowego ograniczania prób.

## P3 — rzeczywiście działające platformy

### Windows
- [ ] Montowany zaszyfrowany wolumin KRYPTA, zwykłe operacje plikowe i transparentne szyfrowanie podczas zapisu.
- [ ] Działające dyski zewnętrzne USB/SSD/HDD; odłączenie podczas I/O, ponowne podłączenie i niezawodne odzyskiwanie.
- [ ] Podpisane, zgodne z polityką systemu komponenty, bezpieczne aktualizacje i deinstalacja bez utraty danych.
- [ ] Systemowy C: / boot — rozruch, uśpienie, aktualizacje Windows i recovery zweryfikowane na oddzielnych urządzeniach.
- [ ] Testy uprawnień, reparse points, ACL, współbieżności, pamięci i błędów I/O.

### Linux
- [ ] Montowanie i zwykła praca na plikach: katalogi, prawa, timestamps, blokady, rename/unlink, duże pliki.
- [ ] Test na kilku wersjach jądra i dystrybucjach, wraz z rzeczywistą awarią oraz odtwarzaniem woluminu.
- [ ] Bezpieczne zamykanie i odmontowywanie oraz aktualizacje nieunieważniające danych.

### Android
- [ ] Stabilny, podpisany APK i odtwarzalne buildy; weryfikacja na fizycznych urządzeniach i różnych API/OEM.
- [ ] Ochrona plików z integralnością, bezpieczną obsługą outputu i sprawdzonym odzyskiwaniem/przenoszeniem sekretów.
- [ ] Jawne określenie zasięgu ochrony: wybrane pliki/kontener aplikacji versus pełna integracja z uprzywilejowanym OS.
- [ ] Jeśli obiecywana jest ochrona całej pamięci: osobny rzeczywiście wdrożony kompatybilny komponent systemowy.

### Password Shield
- [ ] Bezpieczny sejf z niezależnym formatem, integralnością i procedurą odzyskiwania.
- [ ] Reautoryzacja przed ujawnieniem sekretu, osłona schowka i czasu przechowywania w pamięci, testy nadużyć.

## P4 — wiarygodność, prywatność, wydajność i wydania

- [ ] Testy porównawcze z istniejącymi systemami na identycznym sprzęcie, scenariuszach i modelu zagrożeń.
- [ ] Niezależny audyt kryptografii, parserów, kluczy, integracji z OS i procesu aktualizacji; usunięcie krytycznych usterek.
- [ ] Testy penetracyjne, przejrzyste raporty i powtarzalna dokumentacja zachowania pod obciążeniem.
- [ ] Brak obligatoryjnego konta, telemetryki, zewnętrznego serwera odblokowania lub ukrytej zależności od innych projektów.
- [ ] Podpisane, wersjonowane i możliwe do niezależnej weryfikacji wydania instalatorów i plików przywracania.
- [ ] Kompletne 11 lokalizacji komunikatów i przegląd ich zgodności, szczególnie tekstów dot. bezpieczeństwa.
- [ ] Polityka luk, reakcji na incydenty, rotacji podpisów i wycofywania błędnej aktualizacji.
- [ ] Końcowa kwalifikacja wymagań wydania 1.0 podpisana dopiero po rzeczywistym przeglądzie dowodów.

## Definicja statusów

**Zaimplementowane** — kod udostępnia konkretną funkcję.  
**Zweryfikowane w CI** — określone testy na określonych konfiguracjach przeszły.  
**Zweryfikowane na sprzęcie** — powtarzalne testy na fizycznym sprzęcie i określonej wersji OS.  
**Gotowe do użytku produkcyjnego** — spełnione właściwe bramki i niezależnie ocenione ryzyko.  
**Niezaimplementowane** — funkcja nie istnieje w użytkowym produkcie.

Nigdy nie zamieniać tych kategorii w jedną etykietę „działa”. Nadmierne nazewnictwo typu „eksperyment” w prezentacji produktu zastępujemy **dokładnym stanem funkcji i dowodami**; nie ukrywamy informacji potrzebnych do oceny bezpieczeństwa.

**Zasada nadrzędna:** KRYPTA ma być w pełni działająca i możliwie najlepsza według obiektywnych kryteriów. Nie ma zgody na wydanie półproduktu jako ukończonego produktu ani na fałszywe gwarancje.
