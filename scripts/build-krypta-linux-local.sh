#!/usr/bin/env bash
# KRYPTA development build only. NEVER accesses block devices or /dev disks.
# Builds on this computer to avoid GitHub Actions hosted-runner availability.
set -euo pipefail
cd "$(dirname "$0")/.."
command -v python3 >/dev/null || { echo 'Python 3.10+ is required' >&2; exit 1; }
python3 -c 'import sys; assert sys.version_info >= (3, 10)'
echo '[1/4] Install dependencies in current Python environment'
python3 -m pip install -e '.[test]' 'pyinstaller==6.16.0'
echo '[2/4] Run full security regression suite'
python3 -m pytest -q
echo '[3/4] Build local standalone Linux desktop binary'
python3 -m PyInstaller --noconfirm --clean --onefile --windowed \
  --distpath dist/local-linux-volume-lab \
  --workpath build/local-linux-volume-lab \
  --name KRYPTA-Linux-x64-VolumeLab-DEV \
  krypta/desktop_entry.py
exe=dist/local-linux-volume-lab/KRYPTA-Linux-x64-VolumeLab-DEV
test -s "$exe"
chmod +x "$exe"
echo '[4/4] Test packaged ELF with synthetic data only'
for arg in --self-test --volume-self-test --filesystem-self-test \
           --fuse-self-test --paged-volume-self-test; do
  "$exe" "$arg"
done
(cd dist/local-linux-volume-lab && \
 sha256sum KRYPTA-Linux-x64-VolumeLab-DEV \
 > KRYPTA-Linux-x64-VolumeLab-DEV.sha256)
echo "SUCCESS: local tested development ELF: $exe"
echo 'Not signed, audited or authorized for whole-disk encryption.'
