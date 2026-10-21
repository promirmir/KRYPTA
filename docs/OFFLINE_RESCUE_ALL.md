# KRYPTA — niezależne odzyskiwanie wszystkich plików PFS/2

**Etap produktu:** samodzielne narzędzie konsolowe do odzyskiwania wyłącznie
sztucznych / wcześniej zarchiwizowanych obrazów \`.kpv\`. Nie odszyfrowuje
całych dysków i nie zastępuje awaryjnego środowiska bootowalnego. Nie zostało
jeszcze niezależnie zaudytowane. Nie używać do jedynej kopii ważnych danych.

## Co umożliwia

W sytuacji, gdy aplikacja graficzna nie uruchamia się lub hasło zostało
utracone, **nie jest konieczne uruchomienie GUI**. Wystarczą:

- Zaszyfrowany obraz PVIMG/1 + PFS/2, czyli zwykły plik \`*.kpv\`
- Pasujący plik opakowania klucza \`*.pvkey\`
- **Oddzielny losowy 32-bajtowy plik klucza odzyskiwania** utworzony wcześniej
- Aktualny **zewnętrzny zaufany \`receipt\`**, zachowany niezależnie od obrazu
- Nowy, nieistniejący folder wyjściowy z wystarczającą ilością miejsca

Narzędzie odblokowuje DEK przy pomocy recovery i klucza PVKEY/1, sprawdza
identyfikator obrazu, uwierzytelnia bieżący zewnętrzny \`receipt\`, a następnie
**weryfikuje wszystkie pliki przed zapisaniem jakiegokolwiek plaintextu**.
Obraz źródłowy jest otwierany w trybie \`read_only=True\`; nie przycina
uszkodzonego ogona logu po awarii. Przy sukcesie do NOWEGO folderu trafiają
wszystkie dostępne pliki oraz \`KRYPTA_RESCUE_COMPLETE.json\`.

Manifest zawiera nazwy, rozmiary, skróty SHA-256, identyfikator obrazu oraz
wskazany \`receipt\`. **Manifest NIE jest podpisany kryptograficznie.**
Może ułatwić lokalną kontrolę przywróconych plików, ale nie jest zaufanym
źródłem danych przeciwko atakującemu mającemu dostęp do hosta.

## Windows / Linux — użycie bez GUI

Zachowaj powyższe pliki poza publicznym repozytorium. W terminalu, po
zainstalowaniu zależności projektu, możesz uruchomić:

\`\`\`bash
python -m research.paged_rescue \
  --image /private/test.kpv \
  --envelope /private/test.pvkey \
  --recovery /offline/independent-recovery.bin \
  --trusted-receipt REPLACE_WITH_64_LOWERCASE_HEX \
  --new-directory /private/UNUSED-RESTORED-DIR \
  --acknowledge-plaintext-test-only
\`\`\`

Z przygotowanego i zweryfikowanego oddzielnego EXE/ELF, po zakończonym
workflow dystrybucji, wywołaj analogiczne argumenty:

\`\`\`text
KRYPTA-Windows-x64-Rescue.exe --image ... --envelope ... --recovery ... --trusted-receipt ... --new-directory ... --acknowledge-plaintext-test-only
./KRYPTA-Linux-x64-Rescue --image ... --envelope ... --recovery ... --trusted-receipt ... --new-directory ... --acknowledge-plaintext-test-only
\`\`\`

Wersja konsolowa ma też test na samych syntetycznych danych:
\`KRYPTA-Windows-x64-Rescue.exe --self-test\` lub
\`./KRYPTA-Linux-x64-Rescue --self-test\`. Ten test jest wymagany przed
publikacją plików.

## Przerwanie / błąd

W razie wykrycia uszkodzenia lub niewłaściwego \`receipt\` żaden folder
wynikowy nie powstaje. Podczas normalnego błędu zapisu narzędzie próbuje
usunąć wyłącznie własne, nowo utworzone pliki, identyfikując je po inode.
**Nagłe zabicie procesu lub utrata zasilania może pozostawić
niekompletny folder z JAWNYMI plikami.** Folder bez kompletnego manifestu
nie świadczy o powodzeniu odzyskiwania; nie udostępniaj go innym.

Pliki wynikowe są **odszyfrowane i niezabezpieczone kryptograficznie**.
Przechowuj je na lokalnym, odpowiednio zabezpieczonym nośniku. Na Windows
uprawnienia ACL katalogów i dowiązania NTFS wymagają dalszego audytu.
Operacje na wrogich, współdzielonych lub modyfikowanych równolegle folderach
nie są jeszcze obsługiwane jako środowisko wysokiego zaufania.

Tryb ten NIE przywróci danych, gdy brakuje odpowiedniego \`.pvkey\`,
oddzielnego klucza recovery albo poprawnego, niezależnego bieżącego receipt;
ani gdy zaszyfrowana treść jest nieodwracalnie uszkodzona. **Zielony CI nie
zastępuje kopii zapasowej i praktycznego testu przywrócenia.**
# Bezpieczeństwo katalogu docelowego (PR #25)

Wybierz NOWY katalog pod prywatnym, zaufanym katalogiem lokalnym. Eksport
odrzuca symlinki/junctions, niezaufane uprawnienia i nieobsługiwane systemy
plików. Windows: lokalny stały dysk NTFS; Linux: obsługiwane lokalne systemy
plików. Nie zmieniaj praw współdzielonego katalogu, aby obchodzić odmowę.
[Szczegóły uchwytów, ACL, sprzątania i ograniczeń](RESCUE_OUTPUT_SECURITY.md).
Przegląd niezależny oraz kwalifikacja sprzętowa nadal wymagane; #24 otwarte.
