# KRYPTA — Nadrzędne wymagania projektu (Project Charter)

**Status:** przyjęte na podstawie wymagań właściciela · 2026-10-20  
**Repozytorium:** `promirmir/KRYPTA` · **PRIVATE do osobnej decyzji właściciela**  
**Zasada:** to dokument nadrzędny wobec planów i opisów. Zmiana celów wymaga wyraźnej decyzji właściciela; każdą propozycję odstępstwa należy oznaczyć jako *odstępstwo*, a nie po cichu przedefiniować projekt.

## Cel bez zmian

**KRYPTA ma być autorskim, niezależnym systemem szyfrowania, a nie nakładką na BitLocker, LUKS, VeraCrypt lub inne istniejące systemy.** Zewnętrzne mechanizmy wolno wykorzystać tylko do **diagnostyki, porównania, interoperacyjności lub awaryjnej migracji**, nigdy jako własny silnik KRYPTA.

Zadaniem jest możliwie najwyższa **udowodniona** odporność na współczesne i przyszłe ataki, również wykonywane przez wysoce autonomiczne AI i przyszłe komputery kwantowe. Kierunek „lepiej niż BitLocker, rozwiązania wojskowe czy systemy F-16” jest **aspiracją dotyczącą poziomu bezpieczeństwa**, a nie weryfikowalnym porównaniem z nieujawnionymi systemami wojskowymi ani deklaracją niełamliwości.

## Funkcje obowiązkowe

1. **Własny transparentny silnik woluminów:** po odblokowaniu dysk działa zwyczajnie; **każdy nowy i modyfikowany plik jest szyfrowany automatycznie podczas zapisu**, nie przez okresowe skanowanie katalogów.
2. **Windows:** własne szyfrowanie woluminu systemowego z ochroną przed rozruchem; osobne zarządzanie nośnikami USB/SSD/HDD; produkt końcowy `.exe`.
3. **Linux:** własny silnik ochrony woluminów, integracja z warstwą pamięci masowej/montowania bez ręcznego szyfrowania plików; wydanie Linux.
4. **Android:** natywna aplikacja `.apk`, sejf danych/kluczy i na tyle pełna ochrona pamięci, na ile pozwalają uprawnienia platformy. **Zwykły APK nie może zastąpić systemowego FBE ani przechwytywać wszystkich zapisów innych aplikacji**; własna pełna integracja wymaga kompatybilnego obrazu OS/komponentu uprzywilejowanego. Nie przedstawiać aplikacji-sandbox jako szyfrowania całego telefonu.
5. **Sejf haseł:** własny izolowany sejf z wymuszeniem ponownej autoryzacji przed ujawnieniem sekretu; żadnych fałszywych deklaracji, że może kontrolować wszystkie hasła innych aplikacji.
6. **PIN-y od 1 cyfry**, w szczególności 4-cyfrowe, dozwolone jako wybór UI. Użytkownik otrzymuje wyjaśnienie korzyści długiego hasła, ale interfejs nie nakłada arbitralnego minimum. **Krótki PIN nie może być jedynym sekretem w trybie reklamowanym jako odporny na odgadywanie offline.** Wymagany niezależny niekopiowalny sekret wysokiej entropii, egzekwowalne ograniczanie prób oraz model odzyskiwania. W trybie bez sprzętu jasno wskazać słabszy poziom ochrony.
7. **Odporność na brute force, odczyt offline, modyfikację danych, przywracanie starych wersji (rollback), manipulację rozruchem, naruszenie łańcucha dostaw i utratę zasilania.** Nie udawać, że opóźnienie programowe uniemożliwia odgadywanie na kopii szyfrogramu.
8. **Algorytmy i architektura:** autorska specyfikacja woluminów, metadanych, kluczy, wersjonowania, uwierzytelnienia, zapisu i recovery; **osobna ścieżka badawcza własnej konstrukcji kryptograficznej**. Dopuszczalne jest używanie przeanalizowanych prymitywów (np. AES-256, SHA-3, ChaCha20-Poly1305) jako komponentów autorskiego systemu. Nowy eksperymentalny schemat nie może automatycznie zastąpić działającego i bezpieczniejszego rozwiązania.
9. **Projektowanie na przyszłość:** kryptografia symetryczna z kluczami ≥256 bitów; gotowość do wymiany algorytmów bez utraty danych; przy wymianie kluczy/signaturach uwzględnić standardy postkwantowe (ML-KEM, ML-DSA), ale nie stosować ich jako zamienników szyfrowania danych. Bez absolutnych gwarancji przyszłej odporności.
10. **Czytelny publiczny nagłówek:** identyfikator `KRYPTA`, wersja formatu, rzeczywiście użyta kryptografia, tryb ochrony klucza i status weryfikacji. Nagłówek jest jawny, **nie zawiera hasła/klucza ani fałszywych twierdzeń, że decryption jest niemożliwe**. Chroniony przed manipulacją poprzez autentykację metadanych po odblokowaniu.
11. **Wygląd:** stonowany, profesjonalny terminalowy Matrix (ciemne tło, zielone akcenty), bez przesadnych ozdobników AI. Wspólne zasady UI.
12. **Języki:** PL, EN, RU, chiński uproszczony, ES, AR, HI, PT, FR, DE, ID na Windows, Linux i Android, z poprawnymi komunikatami bezpieczeństwa.
13. **Prywatność:** projekt niezależny od AuronQ, bez wspólnego repo, kodu, wydawnictw ani infrastruktury; repozytorium **Private** aż do wyraźnego polecenia publicznej publikacji. Offline-first, brak obowiązkowego konta, usługi chmurowej lub telemetrii.
14. **Brak ryzyka dla danych:** rozwojowe buildy nie mogą samoczynnie szyfrować dysków/partycji ani zmieniać BIOS/TPM/rozruchu. Funkcje mogące uniemożliwić rozruch tylko po osobnych testach, kopiach, drodze odzyskania i jawnej zgodzie operatora.

## Kryteria przewagi nad konkurencją

Nie porównujemy się marketingowo samą nazwą algorytmu. Wymagane mierzalne testy: odporność na kopiowanie szyfrogramu i zgadywanie PIN-u, integralność/rollback, bezpieczeństwo rozruchu, odzyskiwanie po awarii, kompatybilność i wydajność, odporność na eskalację uprawnień oraz aktualizowalność algorytmów. Porównanie z niejawnie chronionymi systemami wojskowymi/F-16 **nie jest możliwe do potwierdzenia**.

## Granice techniczne (nie są odstępstwem od celu)

- Brak absolutnie niełamliwego szyfrowania dla każdego nieznanego przyszłego przeciwnika.
- Bezpieczne dane *w spoczynku* nie oznaczają bezpieczeństwa przed złośliwym oprogramowaniem działającym z uprawnieniami użytkownika po odblokowaniu woluminu; konieczna warstwa ochrony systemu.
- Sprzętowy sekret skojarzony z jednym urządzeniem utrudnia przenoszenie dysków — potrzebny osobny model przenośności i recovery.
- Jedyną uczciwą miarą bezpieczeństwa autorskiego szyfru są jego właściwości i testy, nie nieznajomość jego kodu ani odstraszający napis.

## Hierarchia dokumentów

1. Ten `docs/PROJECT_CHARTER.md` — **cele produktu**.
2. `docs/HORIZON_CRYPTO_RFC.md` — eksperymentalna autorska konstrukcja kryptograficzna.
3. `docs/ARCHITECTURE.md`, `docs/ROADMAP.md` — szczegóły implementacji podporządkowane celom.
4. `docs/SECURITY_STATUS.md` — wyłącznie stan **rzeczywiście zaimplementowany i zweryfikowany**.

**Nie utożsamiać wymagań z wdrożeniem.** Stan obecny: prototyp File Vault; brak produkcyjnego systemowego FDE i sprzętowego odpornego na brute force PIN-u.
