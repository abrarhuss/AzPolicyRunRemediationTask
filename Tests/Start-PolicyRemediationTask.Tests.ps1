#Requires -Version 5.1
# Self-contained mock tests. No Azure authentication or resource changes.
$ErrorActionPreference = 'Stop'
$scriptPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Start-PolicyRemediationTask.ps1'
$assignmentId = '/providers/Microsoft.Management/managementGroups/test/providers/Microsoft.Authorization/policyAssignments/test'
$script:passed = 0

function Assert-True {
    param([bool] $Condition, [string] $Message)
    if (-not $Condition) { throw $Message }
}

function Reset-Fixture {
    $script:events = New-Object 'System.Collections.Generic.List[string]'
    $script:powers = @{
        allocated = 'PowerState/stopped'
        deallocated = 'PowerState/deallocated'
        running = 'PowerState/running'
    }
    $script:states = @(
        foreach ($name in 'allocated', 'deallocated', 'running') {
            $subscription = if ($name -eq 'deallocated') { 'sub2' } else { 'sub1' }
            [pscustomobject]@{
                ResourceId = "/subscriptions/$subscription/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/$name"
                PolicyDefinitionAction = 'deployIfNotExists'
                PolicyDefinitionReferenceId = 'first'
            }
        }
        [pscustomobject]@{
            ResourceId = '/subscriptions/sub1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/allocated'
            PolicyDefinitionAction = 'modify'
            PolicyDefinitionReferenceId = 'second'
        }
        [pscustomobject]@{
            ResourceId = '/subscriptions/sub1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/audit-only'
            PolicyDefinitionAction = 'audit'
            PolicyDefinitionReferenceId = 'audit'
        }
        [pscustomobject]@{
            ResourceId = '/subscriptions/sub1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/child-only/extensions/test'
            PolicyDefinitionAction = 'deployIfNotExists'
            PolicyDefinitionReferenceId = 'first'
        }
    )
    $script:failure = ''
    $script:terminalState = 'Succeeded'
    $script:pollCount = 0
    $script:output = @()
    $script:caught = $null
    $script:warnings = @()
}

function Get-Module { param([switch] $ListAvailable, $Name) [pscustomobject]@{ Name = $Name } }
function Import-Module { param($Name, $ErrorAction) $script:events.Add("Import:$Name") }
function Connect-AzAccount { param($Tenant, $Scope, $ErrorAction, $WhatIf) }
function Get-AzPolicyAssignment { param($Id, $ErrorAction) [pscustomobject]@{ Id = $Id } }
function Get-AzPolicyState {
    param([switch] $All, $Filter, $Select, $ErrorAction, $ManagementGroupName)
    $script:states
}
function Get-AzContext { param($ErrorAction) [pscustomobject]@{ Subscription = 'original' } }
function Set-AzContext {
    param($Subscription, $Tenant, $Context, $Scope, $WhatIf, $Confirm, $ErrorAction)
    if ($Context) {
        $script:events.Add('Context:original')
        return $Context
    }
    $script:events.Add("Context:$Subscription")
    [pscustomobject]@{ Subscription = $Subscription }
}
function Get-AzVM {
    param($ResourceGroupName, $Name, [switch] $Status, $DefaultProfile, $ErrorAction)
    $script:events.Add("Read:$Name")
    $expectedSubscription = if ($Name -eq 'deallocated') { 'sub2' } else { 'sub1' }
    Assert-True ($DefaultProfile.Subscription -eq $expectedSubscription) 'Wrong subscription profile used for VM read.'
    if ($script:failure -eq 'missing-power-state') {
        return [pscustomobject]@{ Statuses = @() }
    }
    [pscustomobject]@{ Statuses = @([pscustomobject]@{ Code = $script:powers[$Name] }) }
}
function Start-AzVM {
    param($ResourceGroupName, $Name, $DefaultProfile, $Confirm, $ErrorAction)
    $script:events.Add("Start:$Name")
    if ($script:failure -ne 'startup-timeout') {
        $script:powers[$Name] = 'PowerState/running'
    }
    if ($script:failure -eq 'start' -and $Name -eq 'deallocated') { throw 'Mock startup failure' }
}
function Stop-AzVM {
    param($ResourceGroupName, $Name, $DefaultProfile, $Force, $Confirm, $ErrorAction, [switch] $StayProvisioned)
    $script:events.Add("Stop:$Name")
    if ($script:failure -eq 'restore' -and $Name -eq 'allocated') { throw 'Mock restoration failure' }
    $script:powers[$Name] = if ($StayProvisioned) { 'PowerState/stopped' } else { 'PowerState/deallocated' }
}
function Start-AzPolicyRemediation {
    param($Name, $Scope, $PolicyAssignmentId, $ResourceDiscoveryMode, $ResourceCount, $ErrorAction, $PolicyDefinitionReferenceId, $Confirm)
    $script:events.Add("Submit:$PolicyDefinitionReferenceId")
    Assert-True ($ResourceCount -eq 50000) 'Resource count changed.'
    if ($script:failure -eq 'submit') { throw 'Mock submission failure' }
    [pscustomobject]@{ Name = $Name; ProvisioningState = 'Accepted' }
}
function Get-AzPolicyRemediation {
    param($Name, $Scope, $ErrorAction)
    $script:events.Add('Poll')
    if ($script:failure -eq 'poll') { throw 'Mock polling failure' }
    $script:pollCount++
    $state = if ($script:pollCount -eq 1) { 'Running' } else { $script:terminalState }
    [pscustomobject]@{ Name = $Name; ProvisioningState = $state }
}
function Start-Sleep { param($Seconds) $script:events.Add('Sleep') }

function Invoke-Fixture {
    param([string] $Mode = 'YES', [switch] $Preview)
    try {
        $options = @{}
        if ($Mode) { $options.StartStopVMs = $Mode }
        $script:output = @(. $scriptPath -TenantId 'tenant' -PolicyAssignmentId $assignmentId @options -WhatIf:$Preview -Confirm:$false -WarningVariable capturedWarnings 3>$null 6>$null)
    }
    catch { $script:caught = $_ }
    $script:warnings = @($capturedWarnings)
}

function Test-Case {
    param([string] $Name, [scriptblock] $Body)
    Reset-Fixture
    & $Body
    $script:passed++
    Write-Host "PASS: $Name"
}

Test-Case 'NO preserves submission-only behavior' {
    Invoke-Fixture -Mode NO
    Assert-True (-not $script:caught) "Unexpected error: $script:caught"
    Assert-True ($script:output.Count -eq 2) 'Expected two submitted tasks.'
    Assert-True (@($script:events | Where-Object { $_ -match '^(Read|Start|Stop|Poll):?|^Import:Az.Compute$' }).Count -eq 0) 'NO must not access VM state, import Compute, or poll.'
}

Test-Case 'Omitting StartStopVMs defaults to submission-only behavior' {
    Invoke-Fixture -Mode ''
    Assert-True (-not $script:caught) "Unexpected error: $script:caught"
    Assert-True ($script:output.Count -eq 2) 'Expected two submitted tasks.'
    Assert-True (@($script:events | Where-Object { $_ -match '^(Read|Start|Stop|Poll)' }).Count -eq 0) 'Default must not manage VMs or wait.'
}

Test-Case 'YES deduplicates VMs, waits for all tasks, and restores exact power states' {
    Invoke-Fixture
    Assert-True (-not $script:caught) "Unexpected error: $script:caught"
    Assert-True ($script:output.Count -eq 2) 'Expected two final task objects.'
    Assert-True (@($script:output | Where-Object { $_.ProvisioningState -ne 'Succeeded' }).Count -eq 0) 'Expected final task status.'
    Assert-True ($script:powers.allocated -eq 'PowerState/stopped') 'Stopped VM was not restored with StayProvisioned.'
    Assert-True ($script:powers.deallocated -eq 'PowerState/deallocated') 'Deallocated VM was not deallocated.'
    Assert-True ($script:powers.running -eq 'PowerState/running') 'Running VM was changed.'
    Assert-True (@($script:events | Where-Object { $_ -eq 'Start:allocated' }).Count -eq 1) 'Duplicate policy references restarted a VM.'
    Assert-True (@($script:events | Where-Object { $_ -match '^(Start|Stop):running$|audit-only|child-only' }).Count -eq 0) 'Unexpected VM was changed/read.'
    Assert-True ($script:events.IndexOf('Submit:first') -gt $script:events.IndexOf('Start:deallocated')) 'Remediation started before VM startup.'
    Assert-True ($script:events.IndexOf('Stop:allocated') -gt $script:events.IndexOf('Submit:second')) 'Cleanup ran before all tasks finished.'
    Assert-True ($script:events[$script:events.Count - 1] -eq 'Context:original') 'Original context was not restored.'
}

Test-Case 'WhatIf makes no VM changes and submits no tasks' {
    Invoke-Fixture -Preview
    Assert-True (-not $script:caught) "Unexpected error: $script:caught"
    Assert-True (@($script:events | Where-Object { $_ -match '^(Start|Stop|Submit|Read|Context):' }).Count -eq 0) 'WhatIf performed a VM operation or submission.'
}

foreach ($terminal in 'Failed', 'Canceled', 'Cancelled') {
    Test-Case "Terminal $terminal restores VMs and reports failure" {
        $script:terminalState = $terminal
        Invoke-Fixture
        Assert-True ([bool] $script:caught) 'Expected remediation error.'
        Assert-True ($script:powers.allocated -eq 'PowerState/stopped') 'Failed task left VM running.'
        Assert-True ($script:powers.deallocated -eq 'PowerState/deallocated') 'Failed task left VM allocated.'
        Assert-True (-not $script:events.Contains('Submit:second')) 'Should not submit more tasks after failure.'
    }
}

Test-Case 'Startup failure cleans up both previously started and partially started VMs' {
    $script:failure = 'start'
    Invoke-Fixture
    Assert-True ([bool] $script:caught) 'Expected startup failure.'
    Assert-True ($script:powers.allocated -eq 'PowerState/stopped') 'Previously started VM was not restored.'
    Assert-True ($script:powers.deallocated -eq 'PowerState/deallocated') 'Partially started VM was not restored.'
    Assert-True (-not $script:events.Contains('Submit:first')) 'Remediation was submitted after startup failure.'
}

Test-Case 'Startup timeout uses the 15-minute limit and does not submit remediation' {
    $script:failure = 'startup-timeout'
    Invoke-Fixture
    Assert-True ([bool] $script:caught) 'Expected startup timeout.'
    Assert-True (@($script:events | Where-Object { $_ -eq 'Sleep' }).Count -eq 60) 'Expected sixty 15-second polling intervals.'
    Assert-True (-not $script:events.Contains('Submit:first')) 'Remediation was submitted before the VM was running.'
    Assert-True ($script:powers.allocated -eq 'PowerState/stopped') 'Timed-out VM was not restored.'
}

foreach ($failureCase in 'transitional', 'missing-power-state') {
    Test-Case "Preflight rejects $failureCase without power changes" {
        if ($failureCase -eq 'transitional') { $script:powers.deallocated = 'PowerState/starting' }
        else { $script:failure = $failureCase }
        Invoke-Fixture
        Assert-True ([bool] $script:caught) 'Expected power-state preflight failure.'
        Assert-True (@($script:events | Where-Object { $_ -match '^(Start|Stop|Submit):' }).Count -eq 0) 'Preflight changed resources.'
    }
}

foreach ($failureCase in 'poll', 'submit') {
    Test-Case "Ambiguous $failureCase failure leaves VMs running with recovery warnings" {
        $script:failure = $failureCase
        Invoke-Fixture
        Assert-True ([bool] $script:caught) 'Expected Azure error.'
        Assert-True (-not $script:events.Contains('Stop:allocated')) 'Stopped VMs during a potentially active task.'
        Assert-True ($script:powers.deallocated -eq 'PowerState/running') 'VM should remain running until task status can be checked.'
        Assert-True (($script:warnings -join ' ') -match 'restore these VMs manually') 'Manual restoration warning is missing.'
    }
}

Test-Case 'Restoration failure reports an error and still restores remaining VMs' {
    $script:failure = 'restore'
    Invoke-Fixture
    Assert-True ([bool] $script:caught) 'Expected restoration error.'
    Assert-True ($script:powers.deallocated -eq 'PowerState/deallocated') 'Cleanup did not continue after restoration failure.'
    Assert-True (($script:warnings -join ' ') -match 'could not be restored') 'Restoration warning is missing.'
}

Test-Case 'No eligible policy states perform no VM operations' {
    $script:states = @($script:states | Where-Object { $_.PolicyDefinitionAction -eq 'audit' })
    Invoke-Fixture
    Assert-True (-not $script:caught) "Unexpected error: $script:caught"
    Assert-True (@($script:events | Where-Object { $_ -match '^(Read|Start|Stop|Submit|Poll)' }).Count -eq 0) 'Unexpected resource operation.'
}

Test-Case 'Non-VM remediation still completes with YES' {
    $script:states = @($script:states | Where-Object { $_.ResourceId -like '*/extensions/*' })
    Invoke-Fixture
    Assert-True (-not $script:caught) "Unexpected error: $script:caught"
    Assert-True ($script:output.Count -eq 1) 'Expected one final task object.'
    Assert-True (@($script:events | Where-Object { $_ -match '^(Read|Start|Stop):' }).Count -eq 0) 'Child resource should not trigger VM management.'
}

Write-Host "$script:passed tests passed."
