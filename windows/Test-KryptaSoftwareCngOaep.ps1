# KRYPTA software-only CNG verification harness for GitHub Windows runners.
# NO TPM HARDWARE is used or inferred. Ephemeral *non-persisted* software key.
# No disks, login state, BitLocker, system key protectors or persistent CNG keys changed.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$providerName = 'Microsoft Software Key Storage Provider'
$key = $null
$rsa = $null
$wrongRsa = $null
$rng = $null
$secret = $null
$recovered = $null
$cipher = $null
$badCipher = $null
$result = [ordered]@{
    Schema = 'KRYPTA-SOFTWARE-CNG-SMOKE/1'
    Provider = $providerName
    KeyType = 'ephemeral'
    RsaOaep256RoundTrip = $false
    TamperRejected = $false
    WrongKeyRejected = $false
    HardwareTpmVerified = $false
    HardwarePinAntiHammeringVerified = $false
}
try {
    $params = [System.Security.Cryptography.CngKeyCreationParameters]::new()
    $params.Provider = [System.Security.Cryptography.CngProvider]::new($providerName)
    $params.KeyUsage = [System.Security.Cryptography.CngKeyUsages]::Decryption
    $params.ExportPolicy = [System.Security.Cryptography.CngExportPolicies]::None
    # null is an ephemeral, unnamed key: it is not installed persistently.
    $key = [System.Security.Cryptography.CngKey]::Create(
        [System.Security.Cryptography.CngAlgorithm]::Rsa, $null, $params)
    if ($key.Provider.Provider -ne $providerName -or (-not $key.IsEphemeral)) {
        throw ('Unexpected CNG attributes: provider=' + $key.Provider.Provider + '; ephemeral=' + $key.IsEphemeral + '; name-present=' + [bool]$key.KeyName)
    }
    $rsa = [System.Security.Cryptography.RSACng]::new($key)
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $secret = New-Object byte[] 32
    $rng.GetBytes($secret)
    $cipher = $rsa.Encrypt($secret, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
    $recovered = $rsa.Decrypt($cipher, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
    if ($recovered.Length -ne $secret.Length) { throw 'Unexpected size' }
    $diff = 0
    for ($i=0; $i -lt $secret.Length; $i++) {
        $diff = $diff -bor ([int]$secret[$i] -bxor [int]$recovered[$i])
    }
    if ($diff -ne 0) { throw 'Round-trip mismatch' }
    $result.RsaOaep256RoundTrip = $true

    $badCipher = [byte[]]$cipher.Clone()
    $badCipher[3] = $badCipher[3] -bxor 1
    try {
        $unused = $rsa.Decrypt($badCipher, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
        if ($null -ne $unused) { [Array]::Clear($unused, 0, $unused.Length) }
    } catch [System.Security.Cryptography.CryptographicException] {
        $result.TamperRejected = $true
    }
    if (-not $result.TamperRejected) { throw 'Tampered wrapped key accepted' }

    $wrongRsa = [System.Security.Cryptography.RSA]::Create(2048)
    try {
        $unused = $wrongRsa.Decrypt($cipher, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
        if ($null -ne $unused) { [Array]::Clear($unused, 0, $unused.Length) }
    } catch [System.Security.Cryptography.CryptographicException] {
        $result.WrongKeyRejected = $true
    }
    if (-not $result.WrongKeyRejected) { throw 'Wrong key unwrapped secret' }
} finally {
    foreach ($buf in @($secret, $recovered, $cipher, $badCipher)) {
        if ($null -ne $buf -and $buf -is [byte[]]) { [Array]::Clear($buf, 0, $buf.Length) }
    }
    if ($null -ne $rng) { $rng.Dispose() }
    if ($null -ne $wrongRsa) { $wrongRsa.Dispose() }
    if ($null -ne $rsa) { $rsa.Dispose() }
    if ($null -ne $key) { $key.Dispose() }
}
$result | ConvertTo-Json -Compress -Depth 4
