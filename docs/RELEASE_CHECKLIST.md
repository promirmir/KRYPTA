# RELEASE GATE

- [ ] Każda ścieżka kodu ma testy negatywne, testy awarii i regresji.
- [ ] Niezależny fuzzing parsera / metadanych, w tym OOM i oversized fields.
- [ ] Testy utraty zasilania, uprawnień, zakleszczeń i wymiany nośników.
- [ ] Testy PIN-ów 1, 0000, 1234, silnych losowych haseł + sprzętowych czynników.
- [ ] Testy ochrony offline keyfile skopiowanego lub ujawnionego.
- [ ] Audyt zewnętrzny modelu zagrożeń, kryptografii i aktualizacji.
- [ ] Test bezpiecznego odzysku na urządzeniu, które utraciło TPM.
- [ ] Przetestowane wdrożenie bootloadera w izolowanym środowisku.
- [ ] Instalator podpisany, aktualizacje podpisane, brak telemetrii sekretów.
- [ ] Potwierdzony brak wymyślonych twierdzeń o odporności na przyszłe ataki.