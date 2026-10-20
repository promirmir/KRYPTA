# KRYPTA / PFS2 — wymiana klucza szyfrującego dane (DEK)

**Stan:** wersja programistyczna na zwykłych obrazach testowych \`.kpv\`. W przeciwieństwie do samego zmienienia hasła, ta operacja szyfruje **wszystkie aktualnie widoczne pliki** od początku pod NOWYM, losowym 256-bitowym kluczem danych. Nie zmienia istniejącego obrazu źródłowego.

## Co faktycznie działa

- API \`research.paged_rekey.rotate_pfs2_data_key(...)\` i polecenie \`python -m research.paged_key_cli rotate-volume-key\`.
- Odblokowanie źródła przy użyciu starego długiego hasła lub **starego niezależnego klucza odzyskiwania**. Wymagany jest najnowszy, samodzielnie zaufany \`expected_receipt\` pochodzący spoza obrazu.
- Weryfikacja uwierzytelnionego identyfikatora obrazu, każdego aktualnego pliku, katalogu oraz jego SHA-256, **zanim** zostanie utworzony obraz docelowy. Odrzucane są błędne hasła, klucze, rollback i niespójne metadane.
- Utworzenie NOWEGO \`.kpv\` z \`O_EXCL\`, odrębnym \`image_id\` oraz świeżym losowym kluczem szyfrowania. Kopiowane są wyłącznie istniejące pliki, nie logicznie usunięte dane.
- Nowy, niezależny \`.pvkey\` opakowujący klucz długim NOWYM hasłem przez Argon2id oraz NOWY, niezależny 256-bitowy sekret odzyskiwania. Nie ma współdzielenia klucza źródłowego.
- Po skopiowaniu plików sprawdzenie odczytu pod nowym kluczem, integralności całego PFS2, obu nowych metod odblokowania, a następnie **ponowne otwarcie gotowego obrazu** z jego własnym \`receipt\`.
- Odmowa nadpisywania któregokolwiek istniejącego celu. Przy wykrytym błędzie usuwane są wyłącznie pliki utworzone przez obecną operację, identyfikowane także po inode. Nie usuwa się źródła.
- Prawidłowe zatwierdzenie powoduje wypisanie nowego \`image_id\` i nowego \`receipt\`, które użytkownik musi niezależnie zabezpieczyć.

## Przykład operacji na WYŁĄCZNIE jednorazowych obrazach testowych

Dysponując źródłowym \`original.kpv\`, \`original.pvkey\`, osobnym dotychczasowym kluczem odzyskiwania oraz **aktualnym zaufanym** potwierdzeniem stanu:

\`\`\`bash
python -m research.paged_key_cli rotate-volume-key \
  --image ./original.kpv \
  --envelope ./original.pvkey \
  --expected-receipt 64_HEX_Z_ZAUFANEGO_MAGAZYNU \
  --old-recovery ./original.recovery \
  --new-image ./new.kpv \
  --new-envelope ./new.pvkey \
  --new-recovery ./new.recovery \
  --acknowledge-test-only
\`\`\`

Narzędzie prosi o NOWE hasło bez jego ujawniania w argumentach. Alternatywnie \`--password-fd\` dostarcza nowe hasło anonimowym potokiem; stare hasło można dostarczyć **oddzielnym** potokiem \`--old-password-fd\` zamiast \`--old-recovery\`. Na Linux przy użyciu potoków nie wolno podawać haseł w historii powłoki, zmiennych środowiskowych ani jawnym pliku.

Wynik podaje \`NEW EXTERNAL RECEIPT\`, potrzebny do przyszłej weryfikacji nowego woluminu. Nie wpisuj go jako stałej w kodzie ani nie traktuj pliku na tym samym nośniku jako niezależnego zaufanego magazynu.

## Zagrożenia, których ta zmiana NIE usuwa

**1. Starych kopii nie da się zdalnie unieważnić.** Posiadacz starego obrazu, starego hasła oraz starego \`.pvkey\` nadal może czytać stare dane. Nowe pliki i zmiany dokonane po migracji są już chronione nowym niezależnym kluczem, o ile pozostałe warstwy bezpieczeństwa działają poprawnie.

**2. Źródło pozostaje na dysku.** Kopia migracyjna nie jest bezpiecznym wymazaniem poprzedniego obrazu, starych kopii zapasowych ani danych z sektorów SSD. Usuwanie i niszczenie źródła to osobna, świadomie zatwierdzona operacja użytkownika, która nie jest wykonywana przez KRYPTA.

**3. Brak atomowego commitu między trzema różnymi plikami na systemie hosta.** Jeżeli system straci zasilanie w połowie migracji, może pozostać częściowy plik docelowy. Nie jest on uznawany za udaną migrację. Zaufane potwierdzenie należy przenieść do niezależnego miejsca dopiero po zakończonej weryfikacji.

**4. Brak sprzętowej blokady prób PIN.** Ktoś z kopią nowego \`.pvkey\` może próbować nowych haseł offline. Krótki PIN nadal nie powinien być jedynym sekretem.

**5. 32 MiB na plik, 128 wpisów, płaski katalog i 512 MiB append-log na obraz.** Szyfrowana migracja kopiuje pliki przez pamięć procesu; brak gwarancji wydajności dla ogromnych zbiorów, wsparcia podkatalogów i produkcyjnej semantyki POSIX.

**6. Brak niezależnego audytu i potwierdzenia rzeczywistej odporności na fizyczny zanik zasilania.** Nie używać na systemowych dyskach ani jedynych kopiach danych.

## Dowody

\`tests/test_paged_rekey.py\`: nowy DEK, identyfikator obrazu, nowe opakowania hasła i odzyskiwania, weryfikacja katalogu po odszyfrowaniu, zachowanie źródła, odmowa nadpisania, niepoprawnego starego hasła lub \`receipt\`, uszkodzenie szyfrogramu, symulowana awaria kopiowania i awaria zapisu credential, powiązanie interfejsu poleceń oraz odrzucenie powtórzenia tego samego hasła.

Zobacz także [PVKEY/1](PVKEY_PASSWORD_RECOVERY.md), [PFS/2](PFS2_LARGE_ATOMIC_FILES.md) i [kryteria ukończenia](PRODUCT_ACCEPTANCE.md).
