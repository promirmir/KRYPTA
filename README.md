# KRYPTA

**Niezależny system szyfrowania danych i woluminów — rozwijany z myślą o kompletnym produkcie dla Windows, Linux i Android.**

KRYPTA jest osobnym projektem bezpieczeństwa, niezależnym od AuronQ. Jej zadaniem jest dostarczenie własnego silnika szyfrowania woluminów i zarządzania kluczami, **bez wykorzystywania BitLocker, LUKS ani VeraCrypt jako silnika szyfrującego**. Docelowo chroniony wolumin ma działać normalnie po odblokowaniu, a wszystkie zapisy mają być automatycznie szyfrowane. Produktem końcowym mają być aplikacje i odpowiednie komponenty systemowe dla Windows i Linux oraz aplikacja i możliwe do uzyskania mechanizmy ochrony dla Androida.

**Ambicja jakościowa:** osiągnięcie najlepszego poziomu bezpieczeństwa w mierzalnych zastosowaniach, w tym możliwość niezależnej oceny dla podmiotów o wysokich wymaganiach. To cel, nie obecnie wykazana przewaga ani certyfikacja.

**Obecny stan (20 października 2026): rozwój przed wydaniem produkcyjnym.** Szyfrowanie wybranych plików na komputerze oraz Androidzie jest zaimplementowane. Szyfrowanie dysków systemowych, automatyczna ochrona wszystkich zapisów Windows i sprzętowe zabezpieczenie krótkiego PIN-u **nie są jeszcze gotowymi funkcjami**. Obecnych wersji nie należy używać jako jedynego zabezpieczenia ważnych danych. Nie przeprowadzono niezależnego audytu kryptograficznego.

![KRYPTA desktop interface](assets/matrix-ui.png)

## Zakres produktu i bieżąca dostępność

| Komponent | Faktycznie dostępne | Brakujące elementy do ukończenia |
|---|---|---|
| **File Vault — Windows/Linux** | Szyfrowanie i odszyfrowywanie wskazanych plików; CLI i GUI; AES-256-GCM, Argon2id, uwierzytelnienie i opcjonalny oddzielny plik klucza | Audyt, rozszerzone testy bezpieczeństwa, lepsza kontrola dostępu do pamięci i plików wyjściowych |
| **Encrypted Volume Core** | Własny VIMG/0 z uwierzytelnionymi transakcjami i nowy PVIMG/1 z hierarchicznym indeksem oraz logiczną przestrzenią 1 GiB; oba działają na wydzielonych obrazach plikowych | Skalowalność produkcyjna, kompakcja, sprawdzone odzyskiwanie po awarii, sprzętowa ochrona kluczy |
| **Linux volume** | Odczyt/zapis przez własny silnik KRYPTA i adapter FUSE w ograniczonym woluminie; potwierdzony montaż w jednej maszynie CI | Pełna semantyka systemu plików, wieloplatformowe testy montowania i awarii oraz wdrożenie produkcyjne |
| **Windows Drive Shield** | Kod diagnostyczny i komponenty silnika plikowego | Rzeczywiste montowanie chronionych woluminów, obsługa USB/SSD/HDD, podpisane komponenty i testy odzyskiwania |
| **Windows System Shield** | Dokumentacja architektury | Szyfrowanie dysku systemowego, ochrona rozruchu, sterownik, bezpieczna migracja i odtwarzanie |
| **Android File Vault** | Szyfrowanie/odszyfrowywanie wybranych plików przez KRYPTA-MOBILE/1 i Android Keystore w APK 0.5.0 | Bezpieczny eksport/backup kluczy, testy na fizycznych urządzeniach, stabilna podpisana wersja |
| **Android full-device integration** | Niezaimplementowana | Zwykły APK nie ma uprawnień do zastąpienia szyfrowania całego telefonu; wymaga odpowiedniego komponentu systemowego |
| **Password Shield** | Niezaimplementowany | Sejf sekretów, ponowna autoryzacja, bezpieczne kopie i audyt |
| **Short-PIN protection** | PIN można wprowadzić w File Vault | Brak niezależnej sprzętowej ochrony i ograniczania prób — krótki PIN sam w sobie pozwala na odgadywanie offline |

Szczegółowe dowody i ograniczenia: [Stan bezpieczeństwa](docs/SECURITY_STATUS.md). Wymagania pełnego produktu: [Kryteria ukończenia](docs/PRODUCT_ACCEPTANCE.md) i [karta projektu](docs/PROJECT_CHARTER.md).

## Własna architektura szyfrowania

KRYPTA rozdziela warstwy: format woluminu i jego transakcje, ochronę kluczy, szyfrowanie rekordów, system plików, adapter systemowy i interfejs. Własny projekt formatu, indeksu i zarządzania dostępem nie wymaga wymyślania od podstaw niezweryfikowanego matematycznie szyfru. Sprawdzone prymitywy można wykorzystać w niezależnym silniku KRYPTA.

- **File Vault v2:** losowy klucz danych 256 bitów, AES-256-GCM, Argon2id + HKDF-SHA-256, kontrola integralności każdego fragmentu i końca pliku.
- **KRYPTA-VIMG/0:** transakcyjne zapisy sektorów w małym zaszyfrowanym obrazie i uwierzytelnione metadane.
- **KRYPTA-PVIMG/1:** oddzielny format z hierarchicznym indeksem COW, uwierzytelnionym korzeniem i rzadką logiczną przestrzenią adresową. **Nie zastępuje automatycznie VIMG/0.**
- **HORIZON/0:** konstrukcja szyfrowania rekordów wykorzystująca AES-256-GCM i ChaCha20-Poly1305; nie ma niezależnego dowodu, że taka kompozycja przewyższa sam sprawdzony AEAD.

Samo uwierzytelnianie bloków nie wykryje przywrócenia całego starego, poprawnego obrazu. Tę gwarancję zapewni dopiero niezależnie chroniony i aktualizowany stan kontrolny. Nie jest jeszcze wdrożony. Nie ma też obecnie sprzętowo wymuszanego limitu prób przy krótkim PIN-ie.

## Pobieranie i uruchamianie obecnego kodu

Repozytorium jest **PRIVATE**. Workflow GitHub Actions przygotowuje wewnętrzne pliki Windows `.exe`, Linux ELF i Android `.apk`. Są to kompilacje rozwojowe, nie opublikowane i audytowane wydania. Nie należy udostępniać ich jako gotowego szyfrowania całych urządzeń.

Windows: Python 3.10+ z Tkinterem:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[test]"
python -m krypta gui
```

CLI, przykładowe operacje na **danych testowych**:

```powershell
python -m krypta --help
python -m krypta gen-keyfile example.key
python -m krypta encrypt example.txt example.kry --keyfile example.key
python -m krypta info example.kry
python -m krypta decrypt example.kry recovered.txt --keyfile example.key
python -m pytest -q
```

Hasło jest pobierane interaktywnie, nie z argumentów wiersza poleceń. Operacje nie powinny nadpisywać istniejącego pliku wyjściowego; oryginalny plik pozostaje bez zmian. Używaj jedynie kopii danych, które możesz utracić. Instrukcje kompilacji: [Build and release](docs/BUILD_AND_RELEASE.md); ograniczenia Androida: [Android README](android/README.md).

## Jawny nagłówek szyfrowanych plików

Format `.kry` zawiera czytelny, niezaszyfrowany identyfikator KRYPTA i informacje o zastosowanym mechanizmie ochrony. Komunikat **nie stanowi atestu, podpisu producenta ani dowodu certyfikacji**. Jego uwierzytelnienie następuje w toku poprawnego odszyfrowania. Krótki PIN bez niezależnego silnego sekretu nadal podlega atakom słownikowym na kopię szyfrogramu. Istniejących nagłówków i komunikatów bezpieczeństwa nie wolno zmieniać w sposób, który fałszywie podnosi poziom gwarancji lub łamie kompatybilność plików.

## Bezpieczeństwo i prywatność

KRYPTA jest projektowana jako system offline-first, bez wymaganego konta i telemetrii. Żadne szyfrowanie dysku nie zabezpieczy samo w sobie danych przed złośliwym kodem, który ma uprawnienia do ich odczytania **po odblokowaniu** urządzenia. Przed wydaniem końcowym wymagane są: testy utraty zasilania, odzyskiwania kluczy i danych, odporności na odgadywanie PIN-u, izolacji procesu, parserów, zgodności z systemami i niezależny audyt. Na dziś nie ma podstaw do określania KRYPTA jako certyfikowanej, wojskowo zatwierdzonej, „niełamliwej” ani odpornej na wszystkie przyszłe komputery kwantowe.

## Lokalizacje i rozwój

Interfejsy mają katalog 11 języków: polski, angielski, rosyjski, uproszczony chiński, hiszpański, arabski, hindi, portugalski, francuski, niemiecki i indonezyjski. Tłumaczenia komunikatów bezpieczeństwa wymagają przeglądu przed wydaniem.

Priorytet prac: **ukończenie i weryfikacja silnika woluminów → bezpieczne klucze i odzyskiwanie → realne montowanie Windows/Linux → systemowe szyfrowanie/boot → Android i sejf → testy końcowe i niezależna ocena**. Rozbudowa wyglądu nie może wyprzedzać bezpieczeństwa i podstawowej funkcjonalności.

Wydanie produkcyjne można ogłosić dopiero po spełnieniu [kryteriów ukończenia](docs/PRODUCT_ACCEPTANCE.md). Repozytorium ma pozostać **PRIVATE** aż do wyraźnej decyzji właściciela.
