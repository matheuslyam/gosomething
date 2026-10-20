#Requires -Version 5.1
<#
.SYNOPSIS
  Installs the versioned git hooks into .git/hooks (harness layer 1).
.DESCRIPTION
  .git/hooks is not versioned by git, so the hook sources live in
  scripts/hooks/ and this installer copies them. Run once per fresh clone.
  WHY an installer instead of documentation-only: an uninstalled hook is a
  silently absent harness; the installer fails loud when sources are missing.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent $PSScriptRoot
$Dest = Join-Path $RepoRoot ".git/hooks"
if (-not (Test-Path $Dest)) { Write-Host "INSTALL-HOOKS: FAIL - no .git/hooks (not a git repo?)"; exit 1 }
foreach ($h in @("pre-commit", "commit-msg")) {
  $src = Join-Path $RepoRoot "scripts/hooks/$h"
  if (-not (Test-Path $src)) { Write-Host "INSTALL-HOOKS: FAIL - missing $src"; exit 1 }
  Copy-Item $src (Join-Path $Dest $h) -Force
}
Write-Host "INSTALL-HOOKS: pre-commit + commit-msg installed into $Dest"
exit 0
