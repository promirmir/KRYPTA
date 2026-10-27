# Password Shield — lokalny sejf haseł KRYPTA (Windows / Linux)

**Stan:** funkcja użytkowa w wydaniu rozwojowym. Nie jest to szyfrowanie
całego komputera ani niezależnie audytowany menedżer haseł.

## Jak używać

1. Otwórz aplikację **KRYPTA** i moduł **04 / Password Shield**.
2. Wybierz ścieżkę **nowego** pliku `.ksecrets`. Sejf nigdy nie nadpisuje
   istniejącego pliku podczas tworzenia.
3. Wpisz unikatowe hasło główne o długości **minimum 12 znaków**.
   Opcjonalnie wybierz osobny plik klucza wygenerowany wcześniej w File Vault.
4. Wybierz **CREATE VAULT**, potem **ADD ENTRY** po podaniu nazwy,
   loginu, hasła wpisu i opcjonalnej notatki.
5. **LIST TITLES** ujawnia tylko nazwy rekordów po uwierzytelnieniu.
   **REVEAL 15s** ujawnia wybrany rekord na ekranie maksymalnie na 15 sekund.
   Program celowo nie kopiuje sekretów do schowka.
6. **DELETE ENTRY** usuwa wskazany wpis i zapisuje od nowa zaszyfrowany
   dokument. Wykonaj kopię `.ksecrets` i oddzielnego klucza po każdej zmianie.

## Bezpieczeństwo i kompatybilność

- Przechowuje hasła we własnym schemacie `KRYPTA-SECRETS/1` wewnątrz
  istniejącego **KRYPTA-FILE/2**, korzystającego z Argon2id i AES-256-GCM.
  Nie ma nowego autorskiego, niezweryfikowanego algorytmu.
- Dokument jest odszyfrowywany **do pamięci operacyjnej**; moduł nie
  zapisuje celowo jawnej bazy sekretów do plików tymczasowych.
- Aktualizacja używa nowego zaszyfrowanego pliku tymczasowego, ponownego
  sprawdzenia autentyczności i porównania SHA-256, blokady współpracujących
  procesów oraz `os.replace` na lokalnym systemie plików.
- Odmowa krótkiego PIN-u wynika z braku sprzętowego ograniczania prób
  odgadnięcia kopii zaszyfrowanej bazy.
- Zamknięcie programu podczas operacji jest blokowane. Awaria w trakcie
  zapisu może pozostawić plik `.lock`. Nie kasuj go mechanicznie:
  sprawdź, czy żaden proces nadal nie zapisuje danych; zachowaj kopie i
  zweryfikuj sejf przed ewentualnym usunięciem blokady.
- Brak zabezpieczenia przed złośliwym programem działającym jako ten sam
  użytkownik, odczytem pamięci, zrzutami pamięci, swapem, nagrywaniem ekranu
  oraz przejęciem sesji. System Python/Tk nie gwarantuje wyczyszczenia
  wszystkich kopii hasła z RAM.
- Integralność zaszyfrowanej bazy **nie zapewnia sama w sobie świeżości
  stanu**. Osoba mogąca przywrócić starszą poprawnie zaszyfrowaną kopię
  może cofnąć zmiany; potrzebna jest niezależna zaufana kotwica przeciw
  rollbackowi.
- Nie ma automatycznej synchronizacji między komputerami, migracji do
  Androida, integracji z przeglądarkami ani audytu. Nie przechowuj jeszcze
  jedynych egzemplarzy ważnych sekretów.
- Przed publikacją produkcyjną konieczne są niezależny audyt, testy
  awarii/recovery, aktualizacje bez utraty danych i ochrona środowiska
  uruchomieniowego.

## Testy

`tests/test_password_shield.py` sprawdza utworzenie sejfu, zapis/odczyt,
usunięcie, zły klucz, przekłamanie szyfrogramu, prywatność uprawnień,
odmowę nadpisania i awarie zapisu. `KRYPTA --self-test` w spakowanej
aplikacji Windows/Linux wykonuje pełny test przejścia na plikach
tymczasowych. Są to testy laboratoryjne, nie audyt bezpieczeństwa.
