#Requires -Version 5.1
<#
.SYNOPSIS
  Executable QA gate for gosomething (harness layer 1, see ADR-0012).
.DESCRIPTION
  Runs the deterministic checks (gofmt non-mutating, vet, test, QA-PLAN
  hygiene) and, only on full green, writes .git/qa-stamp binding verdict GO
  to the current staged tree hash. The pre-commit hook rejects any commit
  whose staged tree has no matching stamp, which makes "verdict table before
  commit" an enforced ordering instead of a remembered rule.
  WHY a script instead of prose: v1-v7 history plus two 2026-10-20 incidents
  prove remembered rules are skipped under pressure; code runs every time.
  Exit 0 = GO (stamp written). Exit 1 = red (no stamp).
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent $PSScriptRoot
$Go = "C:\Program Files\Go\bin\go.exe"
$GoFmt = "C:\Program Files\Go\bin\gofmt.exe"
$StampPath = Join-Path $RepoRoot ".git/qa-stamp"

function Fail([string]$msg) { Write-Host "QA-GATE: FAIL - $msg"; exit 1 }
function Step([string]$msg) { Write-Host "QA-GATE: $msg" }

Set-Location $RepoRoot
if (-not (Test-Path $Go)) { Fail "go not found at $Go" }
if (-not (Test-Path $GoFmt)) { Fail "gofmt not found at $GoFmt (non-mutating check requires it)" }

Step "1/4 gofmt check (non-mutating, gofmt -l)"
$bad = & $GoFmt -l cmd internal scripts 2>&1
if ($bad) { Fail "unformatted files: $bad" }

Step "2/4 go vet ./..."
$out = & $Go vet ./... 2>&1
$out | ForEach-Object { Write-Host $_ }
if ($LASTEXITCODE -ne 0) { Fail "go vet red" }

Step "3/4 go test ./..."
$out = & $Go test ./... 2>&1
$out | ForEach-Object { Write-Host $_ }
if ($LASTEXITCODE -ne 0) { Fail "go test red" }

Step "4/4 QA-PLAN hygiene (no per-round files)"
$leak = git status --porcelain | Select-String 'QA-PLAN-.*\.md'
if ($leak) { Fail "per-round QA files must not exist: $leak" }

$tree = (git write-tree 2>&1).Trim()
if ([string]::IsNullOrWhiteSpace($tree)) { Fail "git write-tree returned empty" }
$stamp = "tree=$tree`r`nverdict=GO`r`nat=$([DateTime]::UtcNow.ToString('o'))`r`nby=scripts/qa-gate.ps1`r`n"
# WHY .NET write instead of Set-Content -NoNewline: that switch does not
# exist in Windows PowerShell 5.1 (verified 2026-10-20); ASCII keeps the
# stamp byte-stable for the hook's grep -xF line match.
$stampBody = "tree=$tree`r`nverdict=GO`r`nat=$([DateTime]::UtcNow.ToString('o'))`r`nby=scripts/qa-gate.ps1`r`n"
# WHY distinct names ($StampPath vs $stampBody, never $Stamp/$stamp):
# PowerShell variables are case-insensitive, so $Stamp and $stamp alias the
# same slot — the content assignment silently destroyed the path and
# WriteAllText failed with "invalid characters". Verified 2026-10-20.
[System.IO.File]::WriteAllText($StampPath, $stampBody, [System.Text.Encoding]::ASCII)
Step "GO - stamp written for staged tree $tree"
exit 0
