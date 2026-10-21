# KRYPTA — Volume Lab / GUI testowych obrazów PFS/2

**Cel:** oddzielny moduł Windows/Linux desktop GUI do świadomych operacji na
zaszyfrowanych **zwykłych plikach obrazów** \`.kpv\`, z oddzielnym kluczem
\`.pvkey\` i 256-bitowym sekretem odzyskiwania. Komponent w przygotowanym
PR nie jest jeszcze opublikowanym EXE/ELF. Nie zabezpiecza dysków systemowych.

## Obsługiwane operacje

1. **Utwórz**: tworzy nowy \`.kpv\`, nowy \`.pvkey\` i niezależny 32-bajtowy
   klucz odzyskiwania; Argon2id/AES-GCM chroni losowy klucz woluminu.
   Żaden istniejący plik nie jest nadpisywany.
2. **Weryfikuj**: otwiera istniejący \`.kpv\` po podaniu hasła **albo** pliku
   odzyskiwania. Wymaga niezależnie zaufanego \`receipt\` (64 znaki hex);
   weryfikuje autentyczność nagłówka, identyfikatora, katalogu i plików.
3. **Dodaj plik**: odczytuje wybrany istniejący zwykły plik (maks. **32 MiB**),
   zapisuje zaszyfrowany katalog i bloki metodą atomowego commitu PVIMG,
   nie nadpisując nazwy już istniejącej w obrazie. **Nie usuwa jawnego oryginału.**
4. **Eksportuj**: weryfikuje autentyczność zawartości przed stworzeniem
   nowego jawnego pliku, nie nadpisując istniejącego. **Wynik nie jest szyfrowany.**
5. **Zmień klucz**: migruje wszystkie aktualne pliki do NOWEGO obrazu
   z nowym identyfikatorem, osobnym losowym kluczem danych i nowymi
   metodami odblokowania; źródło pozostaje niezmienione.
6. **Odzyskaj hasło**: tworzy nową kopię opakowania klucza po odblokowaniu
   plikiem odzyskiwania. Nie zmienia klucza danych, więc stary plik kluczy
   i stare hasło pozostają ważne.

Interfejs jest oddzielnym oknem \`Volume Lab (PFS/2)\` uruchamianym z panelu
bocznego zwykłej aplikacji KRYPTA. Moduł **Drive Shield** pozostaje wyłączony,
ponieważ transparentne szyfrowanie fizycznych/systemowych dysków Windows
wciąż nie jest gotowym produktem.

## Krytyczny \`receipt\` i ochrona przed rollback

Każda operacja na już istniejącym zaszyfrowanym obrazie wymaga aktualnego
potwierdzenia stanu od użytkownika, pobranego z **niezależnie zaufanego źródła**.
Po imporcie danych/rotacji interfejs wyświetla **NOWY RECEIPT**, który trzeba
zapisać poza kopiowalnym obrazem i aktualizować po każdej kolejnej zmianie.

Interfejs wyświetla przycisk **„Zapisz receipt do NOWEGO pliku”** po poprawnej
operacji. Tworzy on plik w trybie wykluczającym nadpisywanie. Przed zapisem
aplikacja wyraźnie ostrzega, że przechowywanie `receipt` obok obrazu nie
zapewnia niezależnej ochrony przeciw rollback. Zmiana języka i próba
zamknięcia głównego okna nie przerywa aktywnej operacji zapisu obrazu.
Nadal nie jest to sprzętowy sejf dla najnowszego `receipt`.

- Nie zapisywać automatycznie potwierdzenia odczytanego z niezaufanego obrazu
  jako nowej zaufanej wartości, gdyż usuwałoby to ochronę przed rollback.
- Utrata bieżącego \`receipt\` może uniemożliwić odblokowanie obrazu
  z wymaganym sprawdzeniem stanu. Przechowywać osobną bezpieczną kopię.
- Samo trzymanie \`receipt\` w pliku obok obrazu nie zapewnia ochrony przed
  atakującym, który może cofnąć oba pliki.
- Nadal brak automatycznie utrzymywanego magazynu anti-rollback, odpornego
  na wyłączenie zasilania w każdym momencie.

## Weryfikacja przy zapisie i błędy po zatwierdzeniu

Przed dodaniem pliku silnik musi teraz wykonać **pełną weryfikację
uwierzytelnionej zawartości wszystkich aktualnych plików**. Zgodny
`receipt` i poprawny katalog nie wystarczają, jeśli starsze sektory
zaszyfrowanych danych zostały uszkodzone. Wykrycie błędu wstrzymuje nowy
commit. Po zakończeniu commitu nowy plik i katalog są ponownie sprawdzane.

Jeżeli commit został zatwierdzony, ale **późniejsza weryfikacja zawiedzie**,
interfejs nie zgłasza sukcesu. Wyświetla tylko diagnostyczny
`UNVERIFIED_RECEIPT_RECOVERY_ONLY`, który **nie może być automatycznie
zapisany ani użyty jako zaufane potwierdzenie stanu**. Należy zachować
obraz, oryginały i kopie zapasowe do niezależnej analizy. Stary receipt
może już nie odpowiadać aktualnemu obrazowi.

Powiadomienie o konieczności aktualizacji zaufanego `receipt` pojawia
się tylko po operacjach rzeczywiście **zmieniających obraz** (utworzenie,
import i rotacja). Sama weryfikacja/eksport nie zastępuje receipt.

Gdy tworzenie nowego woluminu nie kończy się poprawnym raportem po
zapisaniu plików kluczy, mechanizm sprząta wyłącznie pliki utworzone
przez tę operację i rozpoznane po identyfikatorze pliku, nie kasując
wcześniejszych plików użytkownika.

## Otwarcie istniejącego obrazu: prawdziwy tryb read-only (nowy etap)

Dla operacji **Weryfikuj** i **Eksportuj** silnik PVIMG korzysta teraz z
otwarcia z deskryptorem systemowym `O_RDONLY`, blokadą współdzieloną
(`LOCK_SH` na POSIX; `LK_NBRLCK` na Windows) i jawnie odrzuca próby
zapisu. Operacja nie obcina niezatwierdzonego ogona logu po przerwanym
zapisie i nie przepisuje bajtów samego obrazu. Pozwala to zbadać integralność
bez automatycznego niszczenia śladów po awarii.

Podczas **Dodaj plik** nadal stosowane jest wyłączne otwarcie zapisywalne;
przed nową transakcją weryfikowana jest cała aktualna zawartość. Weryfikacja
oryginału przy **Zmień klucz** działa tylko do odczytu, a sam nowy
obraz jest zapisywany do oddzielnego pliku. Tak samo odbywa się końcowa
weryfikacja nowego obrazu.

Uwaga: brak modyfikowania pliku obrazu nie gwarantuje niezmienności jego
otoczenia (np. czasów dostępu, snapshotów, metadanych hosta, historii
operacji systemu). Blokady współdzielone wymagają współpracy wszystkich
piszących procesów — niezaufany proces może nie przestrzegać blokad.
Zaufany aktualny `receipt` jest nadal konieczny do wykrywania rollback.
Pełen audyt niezależny i akceptacja na fizycznych systemach pozostają
do wykonania.

## Hasła, odzyskiwanie i ograniczenia

- Wymagane długie hasła; krótki PIN bez ograniczania prób przez sprzęt
  jest podatny na odgadywanie offline po skopiowaniu \`.pvkey\`.
- Klucz odzyskiwania to **sekret równoważny dostępowi**. Bezpiecznie wykonać
  kopię offline, niezależnie od obrazu i hasła.
- Nie udostępniać Volume Lab aplikacji z podniesionymi uprawnieniami
  ani niezaufanym pluginom; aplikacja w Pythonie nie gwarantuje zerowania
  sekretów z RAM.
- PFS/2 ma płaski katalog do 128 plików, ograniczenie **32 MiB na plik**,
  limit 512 MiB fizycznego logu i brak produkcyjnej obsługi ACL, folderów,
  własności i blokad procesów.
- Na Windows brak jeszcze osobnej zweryfikowanej ścieżki ochrony ACL
  oraz pełnej ochrony przed reparse points. Nie używać do jedynej kopii ważnych
  danych. Konieczne są testy na fizycznych maszynach i niezależny audyt.
- Rotacja DEK nie usuwa ani nie unieważnia skradzionych wcześniejszych
  obrazów i ich kluczy.
- Android APK nie implementuje \`Volume Lab\`; używa odrębnego formatu
  i mechanizmu Android Keystore.

## Testy i tworzenie plików wykonywalnych

- \`tests/test_volume_lab.py\`: sztuczne pliki, dwa sposoby odblokowania,
  potwierdzenia stanu, błędne hasła, import/eksport, brak nadpisywania,
  różne klucze obrazów, odzyskiwanie, odmowa symlinków i przekroczenia limitu.
- \`python krypta/desktop_entry.py --paged-volume-self-test\`: pełna ścieżka
  create/import/export/rotate/verify na automatycznie usuwanym obrazie.
- Workflow \`publish-preview.yml\` został uzupełniony o wymóg przejścia
  tego testu **wewnątrz skompilowanego EXE/ELF**, zanim opublikuje nowe wydanie.
- Gdy GitHub-hosted Actions nie przydzielają runnerów, można z zaufanej kopii
  repo na Windows uruchomić \`powershell -File scripts/Build-Krypta-Windows-Local.ps1\`.
  Dla Linux: \`bash scripts/build-krypta-linux-local.sh\`. Oba skrypty
  instalują zależności, wymagają sukcesu pełnego pytest i testów
  spakowanego programu. Nie uruchamiaj przypadkowych kopii skryptów.
- Skrypty lokalne nie podpisują EXE/ELF, nie tworzą APK i nie publikują
  plików jako zaufanych wersji produkcyjnych. Nie obchodzą wymogu audytu.

**Status 21.10.2026:** Volume Lab został zbudowany i opublikowany w
[publicznej wersji rozwojowej dev-7-1](https://github.com/promirmir/KRYPTA/releases/tag/krypta-dev-7-1),
a [testy spakowanych EXE/ELF i proces trzech platform](https://github.com/promirmir/KRYPTA/actions/runs/39661949384)
zakończyły się powodzeniem. Funkcja pozostaje **rozwojowa** i nie została
niezależnie zaudytowana ani sprawdzona na wszystkich rzeczywistych urządzeniach.
Nie wolno jej przedstawiać jako gotowej ochrony jedynych kopii danych,
dysków systemowych czy urządzeń mobilnych.
