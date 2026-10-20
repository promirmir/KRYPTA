"""Non-cryptographic UI advisories: never replace a threat-model analysis."""

def password_warning(password: str, second_factor: bool) -> str:
    if not password:
        return 'Możesz wpisać PIN (nawet 1 cyfrę) lub hasło. Puste hasło jest niedozwolone.'
    if second_factor:
        return ('Dwa składniki: PIN/hasło + plik klucza. To NIE jest sprzętowe ograniczenie '
                'prób. Chroń plik klucza poza nośnikiem.')
    if len(password) <= 4:
        return ('RYZYKO OFFLINE BRUTE FORCE: krótki PIN jako jedyny sekret jest podatny '
                'na zgadywanie po skopiowaniu szyfrogramu. Wybierz drugi składnik.')
    if len(password) < 12:
        return 'Krótki sekret bez niezależnego klucza nadal może być odgadywany offline.'
    return ('Silne, losowe i unikalne hasło znacząco poprawia ochronę. '
            'Brak sprzętowego licznika prób w tym prototypie.')