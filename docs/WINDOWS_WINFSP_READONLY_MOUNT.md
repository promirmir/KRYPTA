# Windows WinFsp experimental read-only mount (source only)

**Research test only. Do not use with sensitive or irreplaceable data.**

After PR #42 (https://github.com/promirmir/KRYPTA/pull/42), native Windows CI verified an ordinary encrypted .kpv test image can be mounted, enumerated, read, and protected against overwrite, create, delete, and rename. This does **not** mean the released EXE can mount a drive or encrypt the operating system.

## Requirements

Windows, Python 3.11, the matching WinFsp runtime, winfspy 0.8.4, pywin32, and the KRYPTA source dependencies. The CI tests pin a hash-verified WinFsp MSI in .github/workflows/tests.yml.

You must possess an **existing** .kpv image, its matching .pvkey envelope, and a separately trusted current 64-character hexadecimal receipt. In a Windows terminal, use an **unused** drive letter:

~~~powershell
python -m tools.windows_mount_readonly --image "C:\test\sample.kpv" --envelope "C:\test\sample.pvkey" --expected-receipt "YOUR_TRUSTED_CURRENT_64_CHAR_RECEIPT" --drive Z: --acknowledge-test-only
~~~

The placeholder receipt is not valid and must be replaced with the exact trusted value. Password entry uses a hidden interactive terminal prompt; the password is not supplied via command-line arguments. Alternatively add --recovery with the path of the separate recovery-secret file.

The tool refuses occupied drives and paths, A:, B:, C:, and physical devices. It verifies the image ID and all live authenticated files against the externally trusted receipt **before** mounting, and opens the backing image itself read-only. Both the owner/SYSTEM read ACL and driver-enforced read-only flag restrict access, while the adapter rejects write operations. Press Enter or Ctrl+C to unmount.

## Important limitations

While mounted, plaintext is accessible to the Windows account that mounted it and to SYSTEM. Indexers, antivirus, backup or other privileged programs may process this plaintext. Python does not guarantee erasure of secrets from memory. This is **not** full-disk or boot-volume encryption, supports no write-enabled mount, and has no independent audit, production installer, cross-device crash recovery guarantee, or complete Windows Explorer compatibility validation. The existing Windows release EXE does not include this source-only mount command.
