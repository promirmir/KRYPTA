# KRYPTA-PVKEY/1 — niezależne odblokowywanie i odzyskiwanie woluminu

**Zaimplementowano:** osobne, wersjonowane i uwierzytelnione opakowanie losowego 256-bitowego klucza obrazu PVIMG, chronione długim hasłem oraz niezależnym **losowym 256-bitowym kluczem odzyskiwania**. Nie zmienia formatu obrazu PFS/1, PFS/2 ani szyfrów sektorowych. Linux FUSE może odblokować obraz przez \`--envelope\` i \`--password-fd\` zamiast podawania 32-bajtowego klucza woluminu w potoku.

## Schemat bezpieczeństwa

- Jeden **losowy** 32-bajtowy klucz obrazu PVIMG/1 pozostaje niezależny od hasła. Służy bezpośrednio silnikowi woluminu po poprawnym rozpakowaniu.
- Hasło: co najmniej 12 znaków Unicode NFC (zalecane długie, losowe hasło/fraza), Argon2id: **64 MiB pamięci, 3 przebiegi, parallelism 2**, świeża losowa sól 32 B, następnie HKDF-SHA-256 i AES-256-GCM.
- Odzyskiwanie: **oddzielne losowe 32 B**, HKDF-SHA-256 z niezależną domeną, AES-256-GCM. Nie jest wyprowadzane z hasła.
- Oba rekordy mają niezależne nonces. Dane dodatkowe AES-GCM obejmują 16-bajtowy identyfikator obrazu, sól i obydwa nonces, co zapobiega dowolnemu zamienianiu rekordów.
- Kanoniczna, ograniczona do 4096 bajtów reprezentacja JSON; odrzucanie zduplikowanych kluczy, nieznanych pól, nieprawidłowych parametrów KDF, błędnych kodowań Base64 i uszkodzonego AEAD. Nie przyjmujemy parametrów KDF podsuwanych przez napastnika.
- Pliki \`.pvkey\` oraz oddzielny plik klucza odzyskiwania tworzone są z \`O_EXCL\` (nie nadpisują istniejących). Na Linux wymagane jest prywatne prawo 0600/0400, właściciel bieżący i zwykłe pliki, bez dowiązań symbolicznych.
- Hasło nie jest przekazywane przez parametry poleceń ani zmienne środowiskowe; aplikacja korzysta z ukrytego promptu albo z deskryptora anonimowego potoku.
- Montowanie wymaga dodatkowo poprawnego **zewnętrznego \`expected_receipt\`** woluminu i sprawdza, czy identyfikator obrazu jest identyczny z tym zapisanym w zaszyfrowanym bundle.

## Przykładowy przebieg — WYŁĄCZNIE syntetyczne obrazy testowe

Najpierw przygotuj prywatny folder (nie przechowuj klucza odzyskiwania na tym samym nośniku na stałe). Na Linux, przy ręcznym uruchomieniu interaktywnego programu z ukrytym promptem:

\`\`\`bash
python -m research.paged_key_cli create \
  --image ./test.kpv \
  --envelope ./test.pvkey \
  --recovery ./separate-recovery.key \
  --acknowledge-test-only
\`\`\`

Wyświetlony **EXTERNAL RECEIPT** należy zachować w niezależnie zaufanym miejscu. Plik klucza odzyskiwania należy bezpiecznie skopiować na inny nośnik, oddzielnie od hasła i zaszyfrowanego obrazu. Nie wykonuj tego na jedynej kopii danych.

Weryfikacja prawidłowego hasła oraz integralności obrazu:

\`\`\`bash
python -m research.paged_key_cli verify \
  --image ./test.kpv \
  --envelope ./test.pvkey \
  --expected-receipt <TRUSTED_64_CHAR_HEX_RECEIPT> \
  --acknowledge-test-only
\`\`\`

Alternatywnie można podać \`--recovery ./separate-recovery.key\`, by zweryfikować i odblokować wolumin bez hasła. Odtworzenie nowego pliku opakowania klucza po utracie hasła:

\`\`\`bash
python -m research.paged_key_cli recover-password \
  --envelope ./test.pvkey \
  --recovery ./separate-recovery.key \
  --new-envelope ./new-test.pvkey \
  --acknowledge-test-only
\`\`\`

Wszystkie te polecenia **odmawiają** pracy bez wyraźnej flagi ryzyka. Po zakończeniu montowania Linux FUSE wypisuje **FINAL RECEIPT**. Można również podać `--final-receipt-out /osobna/sciezka/nowy.receipt`, aby po odmontowaniu utworzyć osobny plik z najnowszym potwierdzeniem. Ścieżka musi być nowa, nie może nadpisywać istniejących plików ani wskazywać zawartości katalogu montowania. **Taki zwykły plik nie jest automatycznie zaufaną kotwicą anty-rollback**; najnowszy receipt trzeba umieścić w niezależnie chronionym miejscu. Zanik zasilania przed zapisaniem zewnętrznego receipt nadal pozostaje problemem projektowym.

Montowanie Linux FUSE bez podawania surowego klucza można wykonać poleceniem \`python -m research.linux_mount_paged\` z parametrami \`--envelope\`, \`--password-fd\` i \`--expected-receipt\`, w prywatnym, pustym katalogu mountpoint 0700 jako użytkownik nie-root. Hasło musi trafić do anonimowego potoku. Jest to narzędzie programistyczne, nie gotowy kreator montowania dla konsumenta.

## Ważne braki — nie obiecujemy bezpieczeństwa sprzętowego

- **Brak ochrony przed atakiem offline na hasło.** Kopia \`.pvkey\` pozwala napastnikowi próbować hasła mimo kosztownego Argon2id. Minimalna długość 12 znaków nie gwarantuje silnego hasła. Krótki PIN (nawet czterocyfrowy) **nie jest** bezpiecznym jedynym sekretem w tym trybie.
- Nie ma **TPM / Secure Enclave**, sprzętowej kontroli liczby prób, automatycznego tworzenia zaufanej aktualnej kotwicy stanu ani ochrony przed rollback po przywróceniu starszej kopii całego obrazu i \`receipt\`.
- Zgubienie obu dróg odblokowania, np. hasła oraz niezależnego klucza odzyskiwania, może uniemożliwić odczyt danych. Plik odzyskiwania to sekret równoważny kluczowi dostępu — chroń go przed kopiowaniem.
- **Zmiana hasła przez odzyskiwanie NIE unieważnia starego hasła** do wcześniej wydanego pliku bundle. Stary klucz dostępu może nadal odszyfrować wolumin. Aby naprawdę odebrać dostęp byłemu posiadaczowi klucza, konieczna jest rotacja właściwego klucza szyfrującego całe dane i migracja do nowego obrazu.
- Na Windows wymagana jest osobna kontrola ACL / reparse points; chmod 0600 nie daje identycznej ochrony jak Unix. Python nie gwarantuje wymazania kopii haseł/kluczy z pamięci.
- Dotychczasowy APK Android nie korzysta z \`PVKEY/1\`, a gotowy EXE desktop jeszcze nie oferuje tego kreatora. Format jest osobnym programistycznym komponentem obrazu PVIMG.
- Ochrona przed root-malware, przejęciem RAM, przyszłymi atakami oraz niezależny audyt nie zostały ukończone.

**Testy:** \`tests/test_paged_keys.py\`, \`tests/test_paged_key_cli.py\` i \`tools/test_kernel_paged_fuse.py\`. W tym ostatnim prawdziwy Linux FUSE odblokowuje obraz hasłem przez nowy bundle, a nie przez surowy klucz. Format pozostaje w fazie rozwoju i nie służy do jedynej kopii ważnych danych.
