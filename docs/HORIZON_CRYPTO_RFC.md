# KRYPTA-HORIZON/0 — autorska konstrukcja badawcza

**Status: RESEARCH EXPERIMENT — nie używać do ochrony prawdziwych danych.**  
**Powiązanie z celami:** [PROJECT_CHARTER](PROJECT_CHARTER.md).  
**Ważne:** jest to nowa, opracowywana na potrzeby KRYPTA *konstrukcja i format*, nie nowy matematycznie niezależny szyfr blokowy. Nie można rzetelnie wykazać, że podobna koncepcja nigdzie nie była publikowana, ani że zapewnia bezpieczeństwo większe niż AES-256.

## Dlaczego własny schemat zamiast „tajnego algorytmu”?

Kod i specyfikacja mają docelowo być jawne. Napastnik powinien móc poznać każdy szczegół poza tajnym kluczem. Użycie nieprzeanalizowanego algorytmu zamiast AES-256 może **obniżyć**, nie zwiększyć poziom bezpieczeństwa. Rozwiązaniem jest własna *konstrukcja łączenia, kluczy, zapisów, integralności i odzyskiwania*, z osobnym laboratorium nowych prymitywów.

## Eksperyment HORIZON v0

Cel: badawcze uwierzytelniane szyfrowanie niewielkiego bloku (typowo 4096 B), z odrębnymi materiałami kluczowymi dla każdego zapisu i dwoma różnymi prymitywami AEAD. *Nie jest to jeszcze montowalny dysk ani szyfrujący sterownik.*

Primitives (dostępne w PyCA cryptography):
- **KDF:** HKDF-SHA-512 rozdziela losowy 256-bitowy klucz główny `MK` na dwa **niezależnie rozdzielone w domenie** klucze `KA` / `KC` po 32 B dla pojedynczego rekordu; używa losowej 32-B soli, indeksu bloku i numeru generacji w info.
- **Warstwa wewnętrzna:** AES-256-GCM, 12-B nonce z generatora losowego; uwierzytelnione dane dodatkowe AAD obejmują pełny jawny nagłówek oraz kontekst użytkownika.
- **Warstwa zewnętrzna:** ChaCha20-Poly1305 z innym 32-B kluczem i niezależnym 12-B nonce; również uwierzytelnia nagłówek/kontekst.
- **Format publiczny:** magic+version, index (uint64), generation (uint64), length (uint32), random salt (32 B), AES nonce (12 B), ChaCha nonce (12 B), ciphertext+2 × 16-B authentication tags. Dane nie są kompresowane.
- **Generacja:** każdy zapis bloku ma nowe salt i nonces z bezpiecznego CSPRNG; format dodatkowo zawiera generację, z którą wiąże się klucze. **Nie** polegać na losowaniu jako jedynym gwarancie niepowtarzalności nonce dla długowiecznych rzeczywistych woluminów — dalsza architektura wymaga trwałego mechanizmu deduplikacji/generacji.
- **Odczyt:** odrzucenie zmienionego nagłówka, indeksu/generacji, AAD, szyfrogramu, tagów i błędnej długości; nie zwraca częściowych danych.
- **Limit wejść:** małe, z góry określone rozmiary do testów (nie uruchamiać na urządzeniach blokowych).
- **Brak połączeń internetowych:** żadne klucze nie są zapisywane ani wysyłane do usług zewnętrznych.

### Model bezpieczeństwa i znane ograniczenia

1. **Dwie warstwy nie oznaczają udowodnionej podwójnej odporności.** Kompozycja jest eksperymentalna. Wymaga analizy wzajemnych założeń i złożoności błędów implementacji.
2. **AI:** automatyzacja ataków i analiza kodu nie stanowią wyłomu matematycznego w silnej kryptografii symetrycznej, ale AI może ułatwić exploit, kradzież kluczy i błędy aktualizacji.
3. **Komputery kwantowe:** wybór wyłącznie symetrycznej kryptografii z kluczami 256-bitowymi jest sensowną strategią ograniczenia znanych ataków typu Grovera; **nie gwarantuje odporności na wszystkie przyszłe maszyny**. RSA, ECDH i podpisy klasyczne nie mogą być jedynym elementem długoterminowego zabezpieczenia przechowywanych kluczy. Dla wymiany kluczy przewidzieć zatwierdzone postkwantowe KEM (np. ML-KEM).
4. **Krótki PIN:** nie jest inputem do HORIZON/0. `MK` ma powstawać losowo; jego odzyskanie wymaga osobnego, sprzętowo chronionego, limitowanego uwierzytelnienia lub niezależnego silnego sekretu. Sam PIN 1/1234 nie wystarcza.
5. **Rollback:** uwierzytelnienie bloku **nie wykrywa** zastąpienia aktualnego rekordu innym, wcześniejszym lecz prawidłowym rekordem bez zewnętrznie chronionej wersji/korzenia integralności. Nie ma jeszcze takiej ochrony.
6. **Odporność na utratę zasilania:** niezaimplementowana. Docelowo własna transakcyjna, COW mapa woluminu + uwierzytelniane metadane + journal/recovery i porównanie z zaufanym stanem monotonicznym.
7. **System:** niezaimplementowane: własna warstwa blokowa/sterownik Windows, moduł Linux, własne komponenty rozruchu, wsparcie pełnej pamięci Android (wymaga integracji z OS), przenośny tryb USB.

## Projekt docelowy: niezależny wolumin KRYPTA

```
aplikacja / filesystem
    ⇕
KRYPTA virtual block device (własna implementacja)
    ⇕
COW transaction manager ─── authenticated metadata tree
    ⇕                       ⇕
HORIZON encrypted sectors   trusted anti-rollback anchor
    ⇕                       ⇕
local physical block storage   recovery & versioned keys
```

Zmiany plików szyfrowane są przez warstwę blokową, bez jawnego ręcznego szyfrowania. Warstwa ma zachować integralność zarówno danych, jak i metadanych; uszkodzenia/cut power powinny być obsługiwane atomowo. Klucze woluminu pozostają niezależne od materiału potrzebnego do PIN. Identyfikatory algorytmów i migracja kluczy umożliwiają przyszłe aktualizacje.

## Plan badań (warunki przejścia kolejnych bram)

- Wprowadzić czysto programowy **referencyjny eksperyment HORIZON/0** na pamięci/testowych blokach. Nigdy nie włączać go domyślnie do File Vault lub systemowego szyfrowania.
- Wykonać testy: roundtrip, złe klucze, różne wielkości, 4 KiB i większe, modyfikacja każdego pola nagłówka, manipulacja tagami, zamiana indeksów, generacji, AAD, wielokrotne zapisy.
- Badać właściwości nonce, wielkości plików, odporność parsera, wydajność i czas odzyskiwania bez ujawniania danych.
- Zaprojektować COW + drzewo integralności + monotoniczne zatwierdzenie stanu (TPM/secure element lub niezależny anchor, bez naiwnego lokalnego licznika).
- Porównać z pojedynczym AES-256-GCM oraz typowymi transparentnymi szyframi woluminów przy tym samym zagrożeniu. Zbędna złożoność bez korzyści jest powodem odrzucenia konstrukcji.
- Dopiero po udokumentowanym przeglądzie i testach bezpieczeństwa rozważać przejście z etapu eksperymentu do właściwego produktu.

**Żadna część HORIZON/0 nie jest obecnie certyfikowana, matematycznie niezłamana, militarnie zweryfikowana ani gotowa do użycia produkcyjnego.**
