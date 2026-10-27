"""Command-line proof of concept. PINs of any nonzero length are accepted."""
import argparse
import getpass
import json
import sys
from pathlib import Path
from .core import (CryptoError, decrypt_file, encrypt_file, file_info, generate_keyfile, verify_file)


def main(argv=None):
    parser = argparse.ArgumentParser(prog='krypta', description='KRYPTA 0.4 alpha (test-file encryption only; no full-disk encryption)')
    sub = parser.add_subparsers(dest='cmd', required=True)
    for name in ('encrypt', 'decrypt'):
        p = sub.add_parser(name)
        p.add_argument('source', type=Path)
        p.add_argument('destination', type=Path)
        p.add_argument('--keyfile', type=Path, help='Opcjonalny drugi, losowy składnik klucza')
    p = sub.add_parser('verify', help='Authenticate full .krypta archive without writing any plaintext')
    p.add_argument('source', type=Path)
    p.add_argument('--keyfile', type=Path)
    p = sub.add_parser('mobile-recover', help='Recover portable KRYPTA-MOBILE/2 Android file using its offline 32-byte keyfile')
    p.add_argument('source', type=Path)
    p.add_argument('destination', type=Path)
    p.add_argument('--recovery-keyfile', type=Path, required=True)
    p = sub.add_parser('mobile-verify', help='Verify portable Android file without writing plaintext')
    p.add_argument('source', type=Path)
    p.add_argument('--recovery-keyfile', type=Path, required=True)
    p = sub.add_parser('gen-keyfile')
    p.add_argument('destination', type=Path)
    p = sub.add_parser('info')
    p.add_argument('source', type=Path)
    sub.add_parser('gui', help='Offline desktop UI (Tkinter)')
    sub.add_parser('volume-status', help='Read-only OS transparent encryption inventory; no disk changes')
    sub.add_parser('physical-disks', help='List real physical disks, read-only (never writes/formats)')
    probe = sub.add_parser('physical-probe', help='Linux USB raw 4KiB read-only diagnostic; NEVER writes')
    probe.add_argument('device', help='Explicit whole-disk path, e.g. /dev/sdb')
    backup = sub.add_parser('physical-backup', help='Linux USB READ-ONLY encrypted backup to new .krypta archive (development)')
    backup.add_argument('device', help='Whole unmounted USB disk, e.g. /dev/sdb')
    backup.add_argument('destination', type=Path, help='New .krypta encrypted archive on another disk')
    backup.add_argument('--keyfile', type=Path, required=True, help='Existing independent secret keyfile (required)')
    recovery = sub.add_parser(
        'physical-restore-image',
        help='Independently verify and restore .krypta USB archive into a NEW .img (NEVER a physical disk)'
    )
    recovery.add_argument('source', type=Path)
    recovery.add_argument('destination', type=Path)
    recovery.add_argument('--keyfile', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.cmd == 'gui':
            from .gui import main as gui_main
            gui_main()
        elif args.cmd == 'mobile-recover':
            from .mobile_recovery import recover_mobile_file
            print(json.dumps(recover_mobile_file(args.source, args.destination, args.recovery_keyfile), indent=2))
        elif args.cmd == 'mobile-verify':
            from .mobile_recovery import verify_mobile_archive
            print(json.dumps(verify_mobile_archive(args.source, args.recovery_keyfile), indent=2))
        elif args.cmd == 'gen-keyfile':
            generate_keyfile(args.destination)
            print('Utworzono klucz. Przechowuj go poza zaszyfrowanym nośnikiem i wykonaj kopię zapasową.')
        elif args.cmd == 'volume-status':
            from .volume_status import inspect_volumes
            print(json.dumps(inspect_volumes(), indent=2, ensure_ascii=False))
        elif args.cmd == 'physical-disks':
            from .physical_devices import inspect_physical_disks
            print(json.dumps(inspect_physical_disks(), indent=2, ensure_ascii=False))
        elif args.cmd == 'physical-probe':
            from .physical_read_probe import probe_linux_usb_readonly, PhysicalProbeError
            try:
                result = probe_linux_usb_readonly(args.device)
            except PhysicalProbeError as exc:
                raise ValueError(str(exc)) from exc
            print(json.dumps(result, indent=2, ensure_ascii=False))
        elif args.cmd == 'physical-restore-image':
            from .physical_restore import restore_usb_archive_to_image
            from .physical_read_probe import PhysicalProbeError
            pw = getpass.getpass('Hasło do przywrócenia archiwum USB: ')
            try:
                report = restore_usb_archive_to_image(
                    args.source, args.destination, pw, args.keyfile
                )
            except PhysicalProbeError as exc:
                raise ValueError(str(exc)) from exc
            print(json.dumps(report, indent=2, ensure_ascii=False))
        elif args.cmd == 'physical-backup':
            from .physical_backup import backup_linux_usb_encrypted
            pw = getpass.getpass('Hasło do zaszyfrowanej kopii USB: ')
            confirm = getpass.getpass('Powtórz hasło: ')
            if pw != confirm:
                raise CryptoError('Hasła nie są identyczne')
            try:
                result = backup_linux_usb_encrypted(args.device, args.destination, pw, args.keyfile)
            except Exception as exc:
                from .physical_read_probe import PhysicalProbeError
                if isinstance(exc, PhysicalProbeError):
                    raise ValueError(str(exc)) from exc
                raise
            print(json.dumps(result, indent=2, ensure_ascii=False))
        elif args.cmd == 'info':
            print(json.dumps(file_info(args.source), indent=2, ensure_ascii=False))
        elif args.cmd == 'verify':
            pw = getpass.getpass('Hasło do weryfikacji archiwum: ')
            print(json.dumps(verify_file(args.source, pw, args.keyfile), indent=2, ensure_ascii=False))
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