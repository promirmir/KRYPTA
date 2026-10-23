# KRYPTA — stały tryb maksymalnie wydajnej realizacji

## Wiążące zasady pracy dla kolejnych sesji i wykonawców

1. **Cel produktu jest stały.** Najpierw bezpieczne szyfrowanie rzeczywistych wymiennych USB/SSD/HDD i woluminów, następnie pozostałe zobowiązania z docs/PROJECT_CHARTER.md i docs/PRODUCT_ACCEPTANCE.md. Nie wolno zastępować brakującej funkcji dokumentacją, interfejsem, nazwą, pustym szkieletem ani samymi testami.
2. **Priorytety zamiast rozproszenia.** Wybieraj najsilniej blokujący etap P0/P1 (poprawność zapisu, autentykacja, odzyskiwanie, nośniki, montowanie, klucze). Jeden spójny PR na kamień milowy; unikaj równoległych nakładających się gałęzi, niepotrzebnych zmian kosmetycznych i wielokrotnych pytań o tę samą zgodę.
3. **Natychmiastowa weryfikacja stanu.** Najpierw pobierz aktualny commit main, otwarte PR-y, wymagane workflow i status blokad. Nie opieraj się wyłącznie na pamięci rozmowy, starym release, ani przewidywaniach.
4. **Działający kod, nie tylko raport.** Dodaj rzeczywistą implementację, testy szczęśliwej ścieżki, scenariusze błędów i awarii, oraz minimalną aktualizację stanu funkcji. Grupuj powiązane modyfikacje w jednym commicie/PR gdy oszczędza to wywołania bez zwiększania ryzyka.
5. **CI to twarda bramka.** Sprawdź osobno Linux/Windows, Python 3.11/3.13, aktualnie wymagane GUI, WinFsp, rescue, security i cross-OS; każde niepowodzenie napraw w PR. Scalaj tylko po sukcesie całości dla dokładnego head SHA. Nie ukrywaj pominiętych ani nadal aktywnych przebiegów.
6. **Dyscyplina bezpieczeństwa danych.** Żadnych zapisów na rzeczywistych dyskach użytkownika, partycjach systemowych, nośnikach bez kopii i możliwości odzyskania. Testy na wyizolowanych plikach/urządzeniach laboratoryjnych. Nie nadaj statusu produkcyjnego przez przejście CI. Po każdej niepewnej transakcji zachowaj wymóg niezależnie zaufanego receipt.
7. **Jednoznaczne dowody.** W wynikach podawaj URL PR, status scalony/otwarty, commit main, które testy faktycznie przeszły oraz co wciąż NIE działa. Odróżniaj kod w branchu, kod scalony, artefakt pobieralny i funkcję sprawdzoną na sprzęcie.
8. **Efektywność komunikacji.** Krótkie, merytoryczne aktualizacje przy dłuższych zadaniach; bez powtarzania planów i bez nakłaniania do Work. Bez deklarowania pracy w tle; kontynuuj bez zbędnych potwierdzeń aż do konkretnego punktu kontrolnego.
9. **Trwały punkt przekazania.** Ten plik i docs/FUNCTION_STATUS.md stanowią źródło dla nowego okna rozmowy, niezależnie od dostępności pamięci ChatGPT. Po zakończeniu kamienia milowego pozostaw repozytorium w stanie pozwalającym wznowić pracę bez odtwarzania historii rozmów.
10. **Bez zgadywania.** Jeśli uprawnienia, CI, narzędzia lub faktyczny wynik nie są dostępne, nazwij dokładnie blokadę. Nigdy nie przedstawiaj nieuruchomionego testu ani pliku do pobrania jako gotowego.

Ten protokół dotyczy wykonywania prac nad KRYPTA i może być stosowany w innych projektach użytkownika z zachowaniem ich własnych priorytetów i odrębnych repozytoriów.
