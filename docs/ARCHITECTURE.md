# ARCHITEKTURA — KRYPTA

## Cele

- Ochrona danych w spoczynku przed nieuprawnionym odczytem po utracie / kradzieży wyłączonego urządzenia.
- Opcjonalne krótkie PIN-y (4 cyfry), z jawnym poziomem ryzyka zależnym od tego, czy klucz jest niewyeksportowalny i limitowany sprzętowo.
- Brak zależności od serwera online do odblokowania danych.
- Osobne profile dla dysku systemowego, dysku zewnętrznego, sejfu haseł i telefonu.
- Każdy komponent niezależnie wydzielony i możliwy do testowania oraz audytu.

## Model kluczy

```
Windows / Android system:
PIN -> TPM/TEE/SE authorization + hardware rate limit -> unwrap random volume key
                                 |
                  measured boot / firmware policy

Portable file container (today):
PIN -> Argon2id -> HKDF (optional random 256-bit keyfile) -> unwrap random DEK -> AES-256-GCM chunks
```

Tych dwóch modeli nie należy utożsamiać. Pojedynczy zaszyfrowany plik nie może sam, bez nieeksportowalnego sekretu sprzętowego, egzekwować zabezpieczającego limitu prób przeciw napastnikowi posiadającemu kopię szyfrogramu.

## Moduł Windows System Shield (plan)

Najpierw adapter do natywnego BitLockera FDE i TPM+PIN, z kontrolami polityk i testami odzyskiwania. To bezpieczniejszy punkt wyjścia niż pisanie niezweryfikowanego sterownika kernel-mode czy własnego UEFI bootloadera. PIN 4-cyfrowy możliwy przy zgodnej polityce Windows; 1-cyfrowy PIN nie jest dozwolony przez standardową konfigurację BitLockera. Żadnych zmian dysku bez kopii i jawnej zgody użytkownika.

## Moduł Drive Shield (plan)

Obsługa szyfrowania woluminów USB/SSD/HDD przy użyciu dojrzałego silnika, a następnie weryfikacja bezpiecznej integracji. Klucz sprzętowy jako osobny opcjonalny czynnik. Potrzebne osobne scenariusze: przenoszenie na inny komputer, odzyskanie przy uszkodzeniu nośnika, brak dostępu do klucza, zmiana hasła i atomowa aktualizacja metadanych. Nie wolno zakładać sprzętowej ochrony PIN-u na przenośnym nośniku.

## Password Shield (plan)

Własny izolowany sejf z dodatkowym uwierzytelnieniem do odsłonięcia sekretu. Kiedy aplikacja otrzyma hasło, nie da się kryptograficznie wymusić, by nie zachowała go w pamięci. Integracje z przeglądarkami / menedżerami haseł wymagałyby odrębnego modelu uprawnień.

## Android Shield (plan)

Natywne Android FBE CE/DE, Android Keystore, Gatekeeper/Weaver i układ bezpieczeństwa. Nie nadpisywać kryptografii systemowej zwykłą aplikacją APK.

## Wymagane wydanie 1.0

Pełny testowany model odzyskiwania danych, testy utraty zasilania, fuzzing parsera, audyt kodu kryptograficznego, kontrola integralności instalatora i aktualizacji, podpisy wydań oraz próby niezależnego naruszenia przez specjalistów bezpieczeństwa.