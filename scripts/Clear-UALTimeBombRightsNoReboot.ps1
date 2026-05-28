#Requires -Version 5.1
$ErrorActionPreference = 'Stop'

$denyRights = @(
    'SeDenyBatchLogonRight',
    'SeDenyInteractiveLogonRight',
    'SeDenyNetworkLogonRight',
    'SeDenyRemoteInteractiveLogonRight',
    'SeDenyServiceLogonRight'
)

$everyoneSid = 'S-1-1-0'
$workDir = Join-Path $env:TEMP ('UALTimeBombClear_' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $workDir -Force | Out-Null

$exportPath = Join-Path $workDir 'current.inf'
$importPath = Join-Path $workDir 'clear.inf'
$databasePath = Join-Path $workDir 'clear.sdb'

secedit.exe /export /cfg $exportPath /areas USER_RIGHTS /quiet | Out-Null
if (-not (Test-Path -LiteralPath $exportPath)) {
    throw "secedit export did not create $exportPath"
}

$current = @{}
$inPrivilegeRights = $false
foreach ($line in Get-Content -LiteralPath $exportPath -Encoding Unicode) {
    if ($line -match '^\s*\[Privilege Rights\]\s*$') {
        $inPrivilegeRights = $true
        continue
    }

    if ($inPrivilegeRights -and $line -match '^\s*\[') { break }

    if ($inPrivilegeRights -and $line -match '^\s*(Se\w+)\s*=\s*(.*)$') {
        $right = $Matches[1]
        $values = @()
        if (-not [string]::IsNullOrWhiteSpace($Matches[2])) {
            $values = $Matches[2].Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
        }
        $current[$right] = @($values)
    }
}

$lines = @(
    '[Unicode]',
    'Unicode=yes',
    '[Version]',
    'signature="$CHICAGO$"',
    'Revision=1',
    '[Privilege Rights]'
)

foreach ($right in $denyRights) {
    $existing = @()
    if ($current.ContainsKey($right)) { $existing = @($current[$right]) }
    $kept = $existing | Where-Object { ($_ -replace '^\*', '') -ne $everyoneSid }
    $lines += ('{0} = {1}' -f $right, ($kept -join ','))
}

$lines | Set-Content -LiteralPath $importPath -Encoding Unicode
$output = & secedit.exe /configure /db $databasePath /cfg $importPath /areas USER_RIGHTS /quiet 2>&1
if ($LASTEXITCODE -ne 0) {
    throw "secedit configure failed ($LASTEXITCODE): $output"
}

$sentinel = 'C:\ProgramData\TimeBomb\bombdropped.txt'
Remove-Item -LiteralPath $sentinel -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Output 'UAL TimeBomb deny rights cleared without reboot.'