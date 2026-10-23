# KRYPTA / P0: bezpieczna kompakcja testowego obrazu szyfrowanego

`research/paged_aead_compaction.py` odzyskuje miejsce przez skopiowanie wyłącznie aktualnie żywych, uwierzytelnionych sektorów do **nowego** obrazu `.kdevtest`. Nowy obraz otrzymuje losową tożsamość i nowe wyprowadzone klucze AES-GCM; źródło jest wyłącznie czytane, a jego niezależnie zaufany receipt musi być podany przez wywołującego.

Przed utworzeniem pliku wynikowego następuje pełna weryfikacja źródła i oszacowanie miejsca. Kopiowanie jest sektorowe, partiami do ośmiu sektorów w jednej transakcji. Po skopiowaniu wynik jest ponownie otwierany i sprawdzany sektor po sektorze. Istniejący plik docelowy nigdy nie jest nadpisywany ani usuwany. Nowy receipt należy osobno zapisać, bez automatycznej promocji zaufania.

**Ograniczenia:** wyłącznie zwykłe pliki testowe `.kdevtest`. To nie jest in-place garbage collection fizycznego USB/SSD/HDD ani przetestowana procedura po zaniku zasilania. Brak przełączania zamontowanego woluminu i autoryzacji zapisów surowych urządzeń. Kod jest krokiem do zarządzania przestrzenią, a nie ukończeniem szyfrowania dysków.
