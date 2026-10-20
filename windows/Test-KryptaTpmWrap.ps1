# KRYPTA / TPM CNG wrapped-secret experimental capability probe
# EXPERIMENTAL - explicitly opt-in only on separate, disposable Windows test hardware.
# The default invocation does not create, read, delete or change any key.
# This script does NOT change BitLocker, disks, firmware, login policies or Secure Boot.
[CmdletBinding()]
param([switch]$RunDisposableTest)

$ErrorActionPreference = 'Stop'
$providerName = 'Microsoft Platform Crypto Provider'
$result = [ordered]@{
    Schema = 'KRYPTA-TPM-WRAP-POC/1'
    Status = 'NOT_RUN'
    Operation = 'RSA-OAEP-SHA256 disposable TPM-provider key round trip'
    ProviderRequested = $providerName
    WrappedKeyRoundTripVerified = $false
    PrivateExportRefused = $null
    CleanupSucceeded = $null
    HardwarePinAntiHammeringVerified = $false
    PcrBindingVerified = $false
    DiskEncryptionEnabled = $false
    Notes = 'Explicit -RunDisposableTest needed; a successful probe is not proof of PIN anti-brute-force.'
}
if (-not $RunDisposableTest) {
    $result | ConvertTo-Json -Depth 4 -Compress
    return
}
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    $result.Status = 'UNSUPPORTED_PLATFORM'
    $result | ConvertTo-Json -Depth 4 -Compress
    return
}

$keyName = 'KRYPTA-ONE-TIME-WRAP-TEST-' + [Guid]::NewGuid().ToString('N')
$provider = [System.Security.Cryptography.CngProvider]::new($providerName)
$key = $null
$rsa = $null
$random = $null
$created = $false
$challenge = $null
$restored = $null
$wrapped = $null
$unexpectedPrivate = $null
try {
    $parameters = [System.Security.Cryptography.CngKeyCreationParameters]::new()
    $parameters.Provider = $provider
    $parameters.KeyUsage = [System.Security.Cryptography.CngKeyUsages]::Decryption
    $parameters.ExportPolicy = [System.Security.Cryptography.CngExportPolicies]::None
    $parameters.KeyCreationOptions = [System.Security.Cryptography.CngKeyCreationOptions]::None
    # A uniquely generated persistent test key is deleted in finally. Do not supply names.
    $key = [System.Security.Cryptography.CngKey]::Create(
        [System.Security.Cryptography.CngAlgorithm]::Rsa, $keyName, $parameters)
    $created = $true
    if ($key.Provider.Provider -ne $providerName) {
        throw 'Unexpected crypto provider'
    }
    $rsa = [System.Security.Cryptography.RSACng]::new($key)
    $challenge = New-Object byte[] 32
    $random = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $random.GetBytes($challenge)
    # The actual random test secret never goes to stdout, a log or a file.
    $wrapped = $rsa.Encrypt($challenge, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
    $restored = $rsa.Decrypt($wrapped, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
    if ($restored.Length -ne $challenge.Length) {
        throw 'Unexpected decrypted test-secret size'
    }
    $diff = 0
    for ($i = 0; $i -lt $challenge.Length; $i++) {
        $diff = $diff -bor ([int]$challenge[$i] -bxor [int]$restored[$i])
    }
    if ($diff -ne 0) {
        throw 'Wrapped test-secret mismatch'
    }
    $result.WrappedKeyRoundTripVerified = $true
    try {
        $unexpectedPrivate = $key.Export([System.Security.Cryptography.CngKeyBlobFormat]::Pkcs8PrivateBlob)
        $result.PrivateExportRefused = $false
        throw 'The key unexpectedly allowed private export'
    } catch [System.Security.Cryptography.CryptographicException] {
        # One export API was rejected; this is NOT an independent extraction-resistance audit.
        $result.PrivateExportRefused = $true
    }
    if ($result.PrivateExportRefused -eq $true) {
        $result.Status = 'WRAP_PROBE_PASSED_NOT_PIN_PROTECTION'
    }
} catch {
    $result.Status = 'UNAVAILABLE_OR_FAILED'
    $result.Notes = 'Hardware probe not validated: provider unavailable or an operation failed; no secret or exception detail logged.'
} finally {
    foreach ($buffer in @($challenge, $restored, $wrapped, $unexpectedPrivate)) {
        if ($null -ne $buffer -and $buffer -is [byte[]]) {
            [Array]::Clear($buffer, 0, $buffer.Length)
        }
    }
    if ($null -ne $random) { $random.Dispose() }
    if ($null -ne $rsa) { $rsa.Dispose() }
    if ($created) {
        try {
            # A fresh handle avoids relying on whether RSACng.Dispose disposed the original handle.
            $cleanupKey = [System.Security.Cryptography.CngKey]::Open($keyName, $provider)
            try {
                $cleanupKey.Delete()
                $result.CleanupSucceeded = $true
            } finally {
                $cleanupKey.Dispose()
            }
        } catch {
            $result.CleanupSucceeded = $false
            $result.Status = 'CLEANUP_FAILED'
            # The generated name is not key material; include it only if manual cleanup is needed.
            $result.DisposableTestKeyNameToRemove = $keyName
            $result.Notes = 'Only a one-time test key may remain. Verify and remove this exact test key with approved tools.'
        }
    }
    if ($null -ne $key) { $key.Dispose() }
}
$result | ConvertTo-Json -Depth 4 -Compress
