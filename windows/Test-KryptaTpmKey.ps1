# KRYPTA TPM platform-key proof of concept — opt-in / disposable.
# No BitLocker, Secure Boot, PCR, key-recovery or disk settings are changed.
# DO NOT run with -RunDisposableTest on a production device without review.
[CmdletBinding()]
param([switch]$RunDisposableTest)

$ErrorActionPreference = 'Stop'
$providerName = 'Microsoft Platform Crypto Provider'
$result = [ordered]@{
    Project = 'KRYPTA'
    Operation = 'Disposable TPM-provider CNG signing-key probe'
    Status = 'NOT_RUN'
    ProviderRequested = $providerName
    SignatureVerified = $false
    PrivateExportRefused = $null
    CleanupSucceeded = $null
    EnforcedPinRetryLimitVerified = $false
    EncryptionEnabled = $false
    Details = 'Requires explicit -RunDisposableTest; never tests PINs or encrypts user data.'
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
$keyName = 'KRYPTA-ONE-TIME-TEST-' + [Guid]::NewGuid().ToString('N')
$key = $null
$rsa = $null
$created = $false
try {
    $parameters = [System.Security.Cryptography.CngKeyCreationParameters]::new()
    $parameters.Provider = [System.Security.Cryptography.CngProvider]::new($providerName)
    $parameters.KeyUsage = [System.Security.Cryptography.CngKeyUsages]::Signing
    $parameters.ExportPolicy = [System.Security.Cryptography.CngExportPolicies]::None
    $parameters.KeyCreationOptions = [System.Security.Cryptography.CngKeyCreationOptions]::None
    # A new GUID name is created by this script only. Never open/delete caller-supplied keys.
    $key = [System.Security.Cryptography.CngKey]::Create(
        [System.Security.Cryptography.CngAlgorithm]::Rsa, $keyName, $parameters)
    $created = $true
    if ($key.Provider.Provider -ne $providerName) {
        throw 'Provider mismatch'
    }
    $rsa = [System.Security.Cryptography.RSACng]::new($key)
    $challenge = New-Object byte[] 32
    $random = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $random.GetBytes($challenge) } finally { $random.Dispose() }
    $signature = $rsa.SignData(
        $challenge, [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    if (-not $rsa.VerifyData(
        $challenge, $signature, [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)) {
        throw 'Challenge-response verification failed'
    }
    $result.SignatureVerified = $true
    try {
        $privateBytes = $key.Export([System.Security.Cryptography.CngKeyBlobFormat]::Pkcs8PrivateBlob)
        if ($null -ne $privateBytes) {
            [Array]::Clear($privateBytes, 0, $privateBytes.Length)
        }
        $result.PrivateExportRefused = $false
        throw 'Private key unexpectedly exportable'
    } catch [System.Security.Cryptography.CryptographicException] {
        $result.PrivateExportRefused = $true
    }
    $result.Status = 'PROBE_PASSED_NOT_PIN_PROTECTION'
} catch {
    $result.Status = 'UNAVAILABLE_OR_FAILED'
    $result.Details = 'TPM-provider key creation or verification failed. No secrets or exception internals are included.'
} finally {
    if ($null -ne $rsa) { $rsa.Dispose() }
    if ($created) {
        try {
            # Delete ONLY the disposable key that this invocation created.
            $key.Delete()
            $result.CleanupSucceeded = $true
        } catch {
            $result.CleanupSucceeded = $false
            $result.Status = 'CLEANUP_FAILED'
            $result.Details = 'Dispose and delete the uniquely named test key with a reviewed manual recovery process.'
        }
    }
    if ($null -ne $key) { $key.Dispose() }
}
$result | ConvertTo-Json -Depth 4 -Compress
