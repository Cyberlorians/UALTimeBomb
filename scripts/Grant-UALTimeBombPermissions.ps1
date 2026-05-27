#Requires -Version 5.1
<#
.SYNOPSIS
    Grants managed identity permissions for UAL TimeBomb Logic Apps.

.DESCRIPTION
    Run after deploying ualtimebomb-arm, ualtimebomb-disarm, and Check-UALTimeBombQueue.
    Grants Sentinel workspace RBAC to the watchlist-driven workflows and Defender for
    Endpoint application roles to the queue, arm, and disarm Logic App managed identities.

.PERMISSIONS REQUIRED TO RUN
    - Owner or User Access Administrator for Azure RBAC assignment on the Sentinel workspace.
    - A tenant role that can assign app roles to service principals, such as Global Administrator,
      Privileged Role Administrator, Cloud Application Administrator, or Application Administrator.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [string]$SubscriptionId,

    [string]$PlaybookResourceGroup = 'Playbook',

    [string]$SentinelResourceGroup = 'Sentinel',

    [Parameter(Mandatory = $true)]
    [string]$SentinelWorkspaceName,

    [string]$QueueWorkflowName = 'Check-UALTimeBombQueue',

    [string]$ArmWorkflowName = 'ualtimebomb-arm',

    [string]$DisarmWorkflowName = 'ualtimebomb-disarm',

    [string]$DefenderAppId = 'fc780465-2017-40d4-a0c5-307022471b92',

    [string]$MicrosoftThreatProtectionAppId = '8ee8fdad-f234-4243-8f3b-15c294843740',

    [string]$MicrosoftGraphResource = ''
)

$ErrorActionPreference = 'Stop'

function Write-Section {
    param([string]$Name)
    Write-Host ''
    Write-Host "== $Name =="
}

function Invoke-AzCliJson {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)

    $output = & az @Arguments 2>&1
    $exitCode = $LASTEXITCODE
    $text = $output -join [Environment]::NewLine
    if ($exitCode -ne 0) {
        throw "Azure CLI command failed ($exitCode): az $($Arguments -join ' ')$([Environment]::NewLine)$text"
    }
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }
    return $text | ConvertFrom-Json
}

function Get-GraphBaseUri {
    if (-not [string]::IsNullOrWhiteSpace($MicrosoftGraphResource)) {
        return $MicrosoftGraphResource.TrimEnd('/')
    }
    $resource = az cloud show --query endpoints.microsoftGraphResourceId -o tsv
    if ([string]::IsNullOrWhiteSpace($resource)) { return 'https://graph.microsoft.com' }
    return $resource.TrimEnd('/')
}

function Get-LogicAppPrincipalId {
    param([Parameter(Mandatory = $true)][string]$Name)
    $principalId = az logic workflow show --resource-group $PlaybookResourceGroup --name $Name --query identity.principalId -o tsv
    if ([string]::IsNullOrWhiteSpace($principalId)) {
        throw "Logic App '$Name' in resource group '$PlaybookResourceGroup' does not have a system-assigned managed identity."
    }
    return $principalId.Trim()
}

function Grant-AzureRoleIfMissing {
    param(
        [Parameter(Mandatory = $true)][string]$PrincipalId,
        [Parameter(Mandatory = $true)][string]$RoleName,
        [Parameter(Mandatory = $true)][string]$Scope,
        [Parameter(Mandatory = $true)][string]$Reason
    )

    $existing = az role assignment list --assignee $PrincipalId --scope $Scope --role $RoleName --query '[].id' -o tsv
    if ($existing) {
        Write-Host "Already assigned: $RoleName -> $PrincipalId"
        return
    }

    Write-Host "Granting: $RoleName -> $PrincipalId"
    Write-Host "Reason: $Reason"
    if ($PSCmdlet.ShouldProcess($PrincipalId, "Grant $RoleName on $Scope")) {
        az role assignment create `
            --assignee-object-id $PrincipalId `
            --assignee-principal-type ServicePrincipal `
            --role $RoleName `
            --scope $Scope `
            --only-show-errors | Out-Null
    }
}

function Grant-DefenderAppRoleIfMissing {
    param(
        [Parameter(Mandatory = $true)][string]$PrincipalId,
        [Parameter(Mandatory = $true)][string]$RoleValue,
        [string]$ResourceAppId = $DefenderAppId
    )

    $defenderSp = Invoke-AzCliJson @('ad', 'sp', 'show', '--id', $ResourceAppId, '-o', 'json')
    $role = $defenderSp.appRoles | Where-Object { $_.value -eq $RoleValue -and $_.allowedMemberTypes -contains 'Application' -and $_.isEnabled }
    if (-not $role) {
        Write-Warning "App role '$RoleValue' was not found on resource app '$ResourceAppId' in this tenant."
        return
    }

    $url = "$script:GraphBaseUri/v1.0/servicePrincipals/$PrincipalId/appRoleAssignments"
    $existing = Invoke-AzCliJson @('rest', '--method', 'get', '--url', $url, '-o', 'json')
    $alreadyAssigned = $existing.value | Where-Object { $_.resourceId -eq $defenderSp.id -and $_.appRoleId -eq $role.id }
    if ($alreadyAssigned) {
        Write-Host "Already assigned Defender app role: $RoleValue -> $PrincipalId"
        return
    }

    $body = @{
        principalId = $PrincipalId
        resourceId  = $defenderSp.id
        appRoleId   = $role.id
    } | ConvertTo-Json -Compress

    Write-Host "Granting Defender app role: $RoleValue -> $PrincipalId"
    if ($PSCmdlet.ShouldProcess($PrincipalId, "Grant Defender app role $RoleValue")) {
        $token = az account get-access-token --resource $script:GraphBaseUri --query accessToken -o tsv
        Invoke-RestMethod `
            -Method Post `
            -Uri $url `
            -Headers @{ Authorization = "Bearer $token" } `
            -ContentType 'application/json' `
            -Body $body | Out-Null
    }
}

Write-Section 'Set subscription'
az account set --subscription $SubscriptionId | Out-Null
$script:GraphBaseUri = Get-GraphBaseUri
Write-Host "Microsoft Graph endpoint: $script:GraphBaseUri"

Write-Section 'Resolve Sentinel workspace scope'
$workspace = Invoke-AzCliJson @('monitor', 'log-analytics', 'workspace', 'show', '--resource-group', $SentinelResourceGroup, '--workspace-name', $SentinelWorkspaceName, '-o', 'json')
$workspaceScope = $workspace.id
Write-Host "Sentinel workspace scope: $workspaceScope"

Write-Section 'Resolve managed identities'
$queuePrincipalId = Get-LogicAppPrincipalId -Name $QueueWorkflowName
$armPrincipalId = Get-LogicAppPrincipalId -Name $ArmWorkflowName
$disarmPrincipalId = Get-LogicAppPrincipalId -Name $DisarmWorkflowName

[pscustomobject]@{
    CheckUALTimeBombQueue = $queuePrincipalId
    UALTimeBombArm        = $armPrincipalId
    UALTimeBombDisarm     = $disarmPrincipalId
} | Format-List

Write-Section 'Grant Sentinel workspace role'
Grant-AzureRoleIfMissing -PrincipalId $queuePrincipalId -RoleName 'Microsoft Sentinel Contributor' -Scope $workspaceScope -Reason 'Queue checker reads and updates the UALTimeBombARM watchlist through ARM Watchlist REST.'
Grant-AzureRoleIfMissing -PrincipalId $disarmPrincipalId -RoleName 'Microsoft Sentinel Contributor' -Scope $workspaceScope -Reason 'Watchlist-driven disarm workflow reads and updates the UALTimeBombDisarm watchlist through ARM Watchlist REST.'

Write-Section 'Grant Defender for Endpoint application roles'
foreach ($role in @('Machine.Read.All', 'Machine.ReadWrite.All')) {
    Grant-DefenderAppRoleIfMissing -PrincipalId $queuePrincipalId -RoleValue $role
}

Grant-DefenderAppRoleIfMissing -PrincipalId $queuePrincipalId -RoleValue 'AdvancedHunting.Read.All' -ResourceAppId $MicrosoftThreatProtectionAppId

foreach ($principalId in @($armPrincipalId, $disarmPrincipalId)) {
    foreach ($role in @('Machine.Read.All', 'Machine.ReadWrite.All', 'Machine.LiveResponse')) {
        Grant-DefenderAppRoleIfMissing -PrincipalId $principalId -RoleValue $role
    }
}

Grant-DefenderAppRoleIfMissing -PrincipalId $disarmPrincipalId -RoleValue 'AdvancedHunting.Read.All' -ResourceAppId $MicrosoftThreatProtectionAppId

Write-Section 'Done'
Write-Host 'UAL TimeBomb permission assignment pass completed.'
