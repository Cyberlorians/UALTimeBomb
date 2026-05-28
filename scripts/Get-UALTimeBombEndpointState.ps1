#Requires -Version 5.1
$ErrorActionPreference = 'Stop'

$rights = @(
    'SeDenyBatchLogonRight',
    'SeDenyInteractiveLogonRight',
    'SeDenyNetworkLogonRight',
    'SeDenyRemoteInteractiveLogonRight',
    'SeDenyServiceLogonRight'
)

$exportPath = Join-Path $env:TEMP 'ual-timebomb-user-rights.cfg'
secedit.exe /export /cfg $exportPath /areas USER_RIGHTS | Out-Null
$policyLines = Get-Content -Path $exportPath

$result = [ordered]@{
    ComputerName = $env:COMPUTERNAME
    BombDropped = Test-Path -LiteralPath 'C:\ProgramData\TimeBomb\bombdropped.txt'
}

foreach ($right in $rights) {
    $line = $policyLines | Where-Object { $_ -like "$right*" } | Select-Object -First 1
    $result[$right] = [bool]($line -match '\*S-1-1-0' -or $line -match 'S-1-1-0')
}

[pscustomobject]$result | ConvertTo-Json -Compress