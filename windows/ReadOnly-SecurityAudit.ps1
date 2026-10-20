# Projekt KRYPTA 0.2.0-alpha — tylko odczyt. Windows PowerShell 5.1+.
# NIE szyfruje, NIE zmienia konfiguracji, NIE eksportuje kluczy odzyskiwania.
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

function Try-Read {
    param([scriptblock]$Action)
    try { & $Action } catch { $null }
}

$os = Try-Read { Get-CimInstance -ClassName Win32_OperatingSystem }
$tpm = Try-Read { Get-Tpm }
$secureBoot = Try-Read { Confirm-SecureBootUEFI }

$drives = @()
$cmd = Get-Command -Name Get-BitLockerVolume -ErrorAction SilentlyContinue
if ($null -ne $cmd) {
    $volumes = Try-Read { @(Get-BitLockerVolume -ErrorAction Stop) }
    if ($null -ne $volumes) {
        foreach ($v in $volumes) {
            $protectors = @()
            if ($null -ne $v.KeyProtector) {
                foreach ($p in @($v.KeyProtector)) {
                    # WYŁĄCZNIE nazwa typu, bez ID, RecoveryPassword, KeyFileName itp.
                    $protectors += [string]$p.KeyProtectorType
                }
            }
            $drives += [ordered]@{
                MountPoint = [string]$v.MountPoint
                EncryptionMethod = [string]$v.EncryptionMethod
                VolumeStatus = [string]$v.VolumeStatus
                ProtectionStatus = [string]$v.ProtectionStatus
                LockStatus = [string]$v.LockStatus
                EncryptionPercentage = $v.EncryptionPercentage
                KeyProtectorTypes = @($protectors)
            }
        }
    }
}

$result = [ordered]@{
    Project = 'KRYPTA'
    Version = '0.2.0-alpha-readonly'
    TimestampUtc = (Get-Date).ToUniversalTime().ToString('o')
    Host = 'Windows'
    OSVersion = if ($null -ne $os) { [string]$os.Version } else { 'unknown' }
    Tpm = [ordered]@{
        Present = if ($null -ne $tpm) { $tpm.TpmPresent } else { $null }
        Ready = if ($null -ne $tpm) { $tpm.TpmReady } else { $null }
        Enabled = if ($null -ne $tpm) { $tpm.TpmEnabled } else { $null }
        LockedOut = if ($null -ne $tpm) { $tpm.LockedOut } else { $null }
    }
    SecureBootEnabled = $secureBoot
    BitLockerVolumes = @($drives)
    Notes = @(
        'Read-only inventory only; no changes performed.',
        'Unknown/null or empty volumes can also mean missing privilege or unsupported cmdlets.',
        'This is not a penetration test, audit certificate or proof of encryption strength.'
    )
}
$result | ConvertTo-Json -Depth 8