# Windows WinFsp experimental read-only mount (source + isolated test EXE)

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

## Windows Volume Lab GUI hand-off (development only)

The **Montuj R/O WinFsp** tab in Volume Lab starts the isolated test mount in a new
interactive Windows console. This is not an in-process WinFsp driver and does not
add write-mounted support to the GUI. The GUI requires a .kpv, matching .pvkey,
separately trusted CURRENT receipt, unused drive letter D:–Z: and optionally a
separate recovery-secret **file**. It intentionally **never accepts a mount
password**: without recovery-file mode, enter the password only at the child's
hidden console prompt. An external receipt is not recovered from the image.

For a packaged Windows GUI, place the *two EXEs from the same tested Actions
artifact* in the **same directory**, without renaming the mount helper:

- `KRYPTA-Windows-VolumeLab-Mount-GUI-TEST.exe`
- `KRYPTA-Windows-ReadOnly-Mount-TEST.exe`

The UI looks for exactly this sidecar filename and will not search PATH.
In a source checkout launched with Windows console Python.exe, the GUI instead
starts `python -m tools.windows_mount_readonly`. Windows and a working native
WinFsp runtime are required in both cases. These are unsigned development
binaries, not generally trusted software installations.

Launching a console **does not mean the mount succeeded**. The separate mount
process checks credentials, trusted receipt and full image integrity before
printing a success message. The console owns the mount: press Enter there to
unmount; closing the GUI does not unmount it. Never close the mount console or
power off a machine as a substitute for orderly shutdown. The GUI launches the
helper as the current user with no elevation and does not pass passwords via
argv, environment variables, shell or GUI controls. The names of paths (including
a recovery-file path) and receipt are present on the subprocess command line.
Only test data with independent backups should be used.

This is a convenience control and not a Windows-native GUI integration or
manual penetration/security audit. A same-account malicious process able to
replace files in the installation directory remains outside the current trust
boundary. Signed distribution and independent review are pending.

## Important limitations

While mounted, plaintext is accessible to the Windows account that mounted it and to SYSTEM. Indexers, antivirus, backup or other privileged programs may process this plaintext. Python does not guarantee erasure of secrets from memory. This is **not** full-disk or boot-volume encryption, supports no write-enabled mount, and has no independent audit, production installer, cross-device crash recovery guarantee, or complete Windows Explorer compatibility validation. The ordinary Windows desktop artifact still does not bundle the WinFsp test helper. Only the paired development artifact described above exposes a GUI launch control when its sidecar helper is present.
