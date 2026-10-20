# KRYPTA / read-only TPM 2.0 capability inventory (Windows PowerShell 5.1+ / pwsh 7).
# Never creates/opens private keys; never changes TPM, BitLocker, Secure Boot or PIN policy.
# Prints JSON only. Avoid publishing output if the machine itself is sensitive.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'

function Try-Value([scriptblock]$Action) {
    try { & $Action } catch { $null }
}

$tpm = Try-Value { Get-Tpm -ErrorAction Stop }
$boot = Try-Value { Confirm-SecureBootUEFI -ErrorAction Stop }
$providerOpen = $false
$providerStatus = 'unknown'

try {
    # Merely open and close the PUBLIC CNG provider; never create any key or sign anything.
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class KryptaNcryptReadOnly {
    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    public static extern int NCryptOpenStorageProvider(out IntPtr provider, string name, int flags);
    [DllImport("ncrypt.dll")]
    public static extern int NCryptFreeObject(IntPtr handle);
}
'@ -ErrorAction Stop
    $handle = [IntPtr]::Zero
    try {
        $status = [KryptaNcryptReadOnly]::NCryptOpenStorageProvider([ref]$handle, 'Microsoft Platform Crypto Provider', 0)
        $providerOpen = ($status -eq 0 -and $handle -ne [IntPtr]::Zero)
        $providerStatus = if ($providerOpen) { 'opened' } else { 'unavailable' }
    }
    finally {
        if ($handle -ne [IntPtr]::Zero) {
            [void][KryptaNcryptReadOnly]::NCryptFreeObject($handle)
        }
    }
}
catch {
    $providerStatus = 'unknown'
}

# Booleans are deliberately $null if commands or access are unavailable.
# Do not treat a positive provider-open result as proof of real key operations or PIN throttling.
$out = [ordered]@{
    schema = 'KRYPTA-TPM-READINESS/1'
    read_only = $true
    tpm = [ordered]@{
        present = if ($null -ne $tpm) { $tpm.TpmPresent } else { $null }
        ready = if ($null -ne $tpm) { $tpm.TpmReady } else { $null }
        enabled = if ($null -ne $tpm) { $tpm.TpmEnabled } else { $null }
        locked_out = if ($null -ne $tpm) { $tpm.LockedOut } else { $null }
        lockout_count = if ($null -ne $tpm) { $tpm.LockoutCount } else { $null }
        lockout_max = if ($null -ne $tpm) { $tpm.LockoutMax } else { $null }
    }
    platform_crypto_provider = [ordered]@{
        name = 'Microsoft Platform Crypto Provider'
        can_open = [bool]$providerOpen
        provider_status = $providerStatus
    }
    secure_boot = [ordered]@{
        enabled = if ($null -ne $boot) { [bool]$boot } else { $null }
    }
    security_assurance = [ordered]@{
        tpm_key_operations_tested = $false
        nonexportable_secret_tested = $false
        pin_anti_hammering_verified = $false
        boot_policy_binding_verified = $false
        recovery_tested = $false
    }
    warning = 'READ-ONLY ADVISORY. No confirmation of PIN brute-force resistance or safe full-disk encryption.'
}
$out | ConvertTo-Json -Depth 7 -Compress