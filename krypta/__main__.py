"""Command-line proof of concept. PINs of any nonzero length are accepted."""
import argparse
import getpass
import json
import sys
from pathlib import Path
from .core import (CryptoError, decrypt_file, encrypt_file, file_info, generate_keyfile)


def main(argv=None):
    parser = argparse.ArgumentParser(prog='krypta', description='KRYPTA 0.4 alpha (test-file encryption only; no full-disk encryption)')
    sub = parser.add_subparsers(dest='cmd', required=True)
    for name in ('encrypt', 'decrypt'):
        p = sub.add_parser(name)
        p.add_argument('source', type=Path)
        p.add_argument('destination', type=Path)
        p.add_argument('--keyfile', type=Path, help='Opcjonalny drugi, losowy składnik klucza')
    p = sub.add_parser('gen-keyfile')
    p.add_argument('destination', type=Path)
    p = sub.add_parser('info')
    p.add_argument('source', type=Path)
    sub.add_parser('gui', help='Offline desktop UI (Tkinter)')
    sub.add_parser('volume-status', help='Read-only OS transparent encryption inventory; no disk changes')
    args = parser.parse_args(argv)
    try:
        if args.cmd == 'gui':
            from .gui import main as gui_main
            gui_main()
        elif args.cmd == 'gen-keyfile':
            generate_keyfile(args.destination)
            print('Utworzono klucz. Przechowuj go poza zaszyfrowanym nośnikiem i wykonaj kopię zapasową.')
        elif args.cmd == 'volume-status':
            from .volume_status import inspect_volumes
            print(json.dumps(inspect_volumes(), indent=2, ensure_ascii=False))
        elif args.cmd == 'info':
            print(json.dumps(file_info(args.source), indent=2, ensure_ascii=False))
        else:
            pw = getpass.getpass('PIN / hasło: ')
            if args.cmd == 'encrypt':
                confirm = getpass.getpass('Powtórz PIN / hasło: ')
                if pw != confirm:
                    raise CryptoError('Hasła nie są identyczne')
                if len(pw) <= 4:
                    print('OSTRZEŻENIE: krótki PIN bez niezależnego, tajnego keyfile pozwala na atak offline.', file=sys.stderr)
                encrypt_file(args.source, args.destination, pw, args.keyfile)
                print('Zaszyfrowano plik. Oryginał NIE został usunięty.')
            else:
                decrypt_file(args.source, args.destination, pw, args.keyfile)
                print('Odszyfrowano plik.')
        return 0
    except (CryptoError, FileNotFoundError, FileExistsError, PermissionError, ValueError, OSError) as exc:
        print(f'BŁĄD: {exc}', file=sys.stderr)
        return 2

if __name__ == '__main__':
    sys.exit(main())