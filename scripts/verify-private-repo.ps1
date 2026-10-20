# KRYPTA — read-only repository visibility verification.
# Requires authenticated GitHub CLI (gh). Makes no changes.
$ErrorActionPreference = 'Stop'
if (-not (Get-Command gh -ErrorAction SilentlyContinue)) { throw 'Install GitHub CLI (gh) first.' }
$json = gh repo view promirmir/KRYPTA --json visibility,isPrivate,nameWithOwner
if ($LASTEXITCODE -ne 0) { throw 'Unable to read GitHub repository.' }
$state = $json | ConvertFrom-Json
if ($state.isPrivate -ne $true -or $state.visibility -ne 'PRIVATE') {
  throw ('SECURITY BLOCK: repository is not private. Visibility: ' + $state.visibility)
}
Write-Host ('Verified private: ' + $state.nameWithOwner) -ForegroundColor Green