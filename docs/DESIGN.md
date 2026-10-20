# KRYPTA UI — matrix-inspired visual language

Intent: a sober technical workstation, not a movie prop. It may suggest a terminal, but every visible security claim must be verifiable.

- Palette: near-black `#080F0C`, muted forest `#0D1812`, phosphor-green `#8CF5A7`, amber for cautions and low-intensity red for threats.
- Type: monospace for technical operations, generous spacing, clear identifiers, unobtrusive status lines.
- No animated fake hacks, moving 0/1 bars, fabricated scanning activity, or meaningless 'SECURE' badges.
- No hidden functions in inactive modules: clicking module name opens honest planned-function screens.
- Entry forms use masked passwords; labels are visible. Plaintext path is shown because the user selects files explicitly.
- Operations run offline in a separate worker thread. The user selects source and destination, and the application never overwrites the destination.
- No automatic deletion or modification of the source file.
- Security status explicitly indicates alpha / not independently audited.
- Optional keyfile and PIN warnings are placed where the decision is made.

## Accessibility and localization

Current UI uses English identifiers with Polish guidance, with room for future full i18n. Tkinter theme requires testing across Windows DPI settings and screen readers before public release. The primary layout currently targets desktop resolutions; small-screen and high-DPI accessibility remain unverified.