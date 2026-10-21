# KRYPTA - read-only PUBLIC source repository visibility check.
# Requires GitHub CLI (gh). Does not modify the repository.
$ErrorActionPreference = 'Stop'
if (-not (Get-Command gh -ErrorAction SilentlyContinue)) { throw 'Install GitHub CLI (gh) first.' }
$json = gh repo view promirmir/KRYPTA --json visibility,isPrivate,nameWithOwner
if ($LASTEXITCODE -ne 0) { throw 'Unable to read GitHub repository.' }
$state = $json | ConvertFrom-Json
if ($state.isPrivate -ne $false -or $state.visibility -ne 'PUBLIC') {
  throw ('KRYPTA public-source status not confirmed; visibility: ' + $state.visibility)
}
Write-Host ('Verified public source repository: ' + $state.nameWithOwner) -ForegroundColor Green
Write-Host 'Public source code does NOT imply that security releases are audited or production-ready.'
