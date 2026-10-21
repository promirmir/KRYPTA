#Requires -Version 5.1
<#
KRYPTA Windows LOCAL developer build, independent of GitHub Actions quota.
Run only in your own trusted checkout of promirmir/KRYPTA.
No admin rights, system encryption, physical disk access or code signing.
The created EXE is a DEVELOPMENT build only.
#>
[CmdletBinding()]
param(
    [string]$PythonExecutable = 'python'
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Set-StrictMode -Version Latest

$Root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location -LiteralPath $Root
$Py = (Get-Command $PythonExecutable -ErrorAction SilentlyContinue)
if (-not $Py) {
    throw "Python 3.10+ is required. Install Python from python.org before running the build."
}
$Python = $Py.Source
& $Python -c 'import sys; assert sys.version_info >= (3, 10), "Python 3.10+ required"'
if ($LASTEXITCODE -ne 0) { throw 'Python version check failed.' }

Write-Host '[1/4] Installing pinned build tooling and project test dependencies'
& $Python -m pip install -e '.[test]' 'pyinstaller==6.16.0'
if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed.' }

Write-Host '[2/4] Running ALL unit and security regression tests'
& $Python -m pytest -q
if ($LASTEXITCODE -ne 0) { throw 'Unit tests failed; refusing to create release artifact.' }

Write-Host '[3/4] Building Windows x64 development EXE'
$Dist = Join-Path $Root 'dist\local-windows-volume-lab'
$Work = Join-Path $Root 'build\local-windows-volume-lab'
& $Python -m PyInstaller --noconfirm --clean --onefile --windowed --distpath $Dist --workpath $Work --name 'KRYPTA-Windows-x64-VolumeLab-DEV' 'krypta/desktop_entry.py'
if ($LASTEXITCODE -ne 0) { throw 'EXE creation failed.' }
$Exe = Join-Path $Dist 'KRYPTA-Windows-x64-VolumeLab-DEV.exe'
if (-not (Test-Path -LiteralPath $Exe -PathType Leaf)) {
    throw 'Packaged EXE was not generated.'
}

Write-Host '[4/4] Exercising compiled EXE, including PFS/2 round trip and key rotation'
foreach ($arg in @('--self-test', '--volume-self-test', '--filesystem-self-test',
                   '--fuse-self-test', '--paged-volume-self-test')) {
    # GUI / --windowed applications can detach from an interactive shell.
    # Explicit -Wait and the returned process exit code prevent false PASS.
    $proc = Start-Process -FilePath $Exe -ArgumentList $arg -PassThru -Wait
    if ($null -eq $proc -or $proc.ExitCode -ne 0) {
        throw "Compiled EXE failed smoke check $arg. DO NOT DISTRIBUTE."
    }
}
$Hash = (Get-FileHash -LiteralPath $Exe -Algorithm SHA256).Hash.ToLowerInvariant()
$HashPath = "$Exe.sha256"
[System.IO.File]::WriteAllText($HashPath,
    "$Hash  KRYPTA-Windows-x64-VolumeLab-DEV.exe$([char]10)",
    [System.Text.Encoding]::ASCII)
Write-Host 'SUCCESS: all local tests and compiled EXE smoke checks passed.'
Write-Host "DEVELOPMENT EXE: $Exe"
Write-Host "SHA256: $Hash"
Write-Host 'No production code signing, disk encryption or security certification implied.'
