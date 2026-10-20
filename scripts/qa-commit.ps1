#Requires -Version 5.1
<#
.SYNOPSIS
  The only supported way to commit in gosomething (harness layer 1+3).
.DESCRIPTION
  Runs scripts/qa-gate.ps1 first; only on GO it calls git commit, where the
  pre-commit hook re-validates the stamp and the commit-msg hook requires a
  QA trailer. Direct `git commit` is denied by opencode permissions and
  rejected by the hook without a stamp, so this script is the single path.
  WHY two scripts instead of one: qa-gate.ps1 stays usable standalone (CI
  parity, manual verification); this wrapper only adds commit plumbing.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$Subject,
  [string]$Body = "",
  [Parameter(Mandatory = $true)][string]$Trailer
)

$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

& "$PSScriptRoot\qa-gate.ps1"
if ($LASTEXITCODE -ne 0) { Write-Host "QA-COMMIT: gate red, commit aborted"; exit 1 }

$fullBody = ($Body.Trim() + "`n`n" + $Trailer.Trim()).Trim()
git commit -m $Subject -m $fullBody
exit $LASTEXITCODE
