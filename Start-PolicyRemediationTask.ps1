#Requires -Version 5.1

<#
.SYNOPSIS
Signs in to Azure and starts remediation for a policy or initiative assignment.
.DESCRIPTION
Uses the latest recorded non-compliant policy states. Only deployIfNotExists
and modify effects support remediation. Initiative assignments get one task
per eligible policy definition reference. Returns Azure remediation objects;
task submission does not mean the resources have been successfully remediated.
.PARAMETER Scope
Target scope type: ManagementGroup, Subscription, ResourceGroup, or Resource.
Specify ScopeId with Scope. Omit both to use the assignment's scope.
.PARAMETER ScopeId
Full Azure resource ID of the target scope, where the assignment must apply.
Supports remediating inherited assignments at a narrower scope.
.PARAMETER StartStopVMs
YES starts stopped/deallocated non-compliant VMs, waits for remediation, and
restores their original power states. NO (default) only submits remediation.
.EXAMPLE
.\Start-PolicyRemediationTask.ps1 -TenantId '<tenant-id>' -PolicyAssignmentId '/subscriptions/<subscription-id>/providers/Microsoft.Authorization/policyAssignments/<assignment-name>'
.EXAMPLE
.\Start-PolicyRemediationTask.ps1 -TenantId '<tenant-id>' -PolicyAssignmentId '<full-assignment-resource-id>' -Scope ResourceGroup -ScopeId '/subscriptions/<subscription-id>/resourceGroups/<resource-group-name>' -WhatIf
.EXAMPLE
.\Start-PolicyRemediationTask.ps1  -TenantId '<tenant-id>' -PolicyAssignmentId '<full-assignment-resource-id>' -Scope 'ManagementGroup' -ScopeId '/providers/Microsoft.Management/managementGroups/<management-group-name>' -StartStopVMs 'YES'
.EXAMPLE
.\Start-PolicyRemediationTask.ps1 -TenantId '<tenant-id>' -PolicyAssignmentId '<full-assignment-resource-id>' -StartStopVMs 'YES'
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $TenantId,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $PolicyAssignmentId,

    [Parameter()]
    [ValidateSet('ManagementGroup', 'Subscription', 'ResourceGroup', 'Resource')]
    [string] $Scope,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string] $ScopeId,

    [Parameter()]
    [ValidateSet('YES', 'NO')]
    [string] $StartStopVMs = 'NO'
)

$ErrorActionPreference = 'Stop'
$PolicyAssignmentId = $PolicyAssignmentId.Trim().TrimEnd('/')
$assignmentPattern = '^(?<Scope>/.+)/providers/Microsoft\.Authorization/policyAssignments/[^/]+$'
if ($PolicyAssignmentId -notmatch $assignmentPattern) {
    throw 'PolicyAssignmentId must be a full Azure policy assignment resource ID, not just its name or GUID.'
}
$assignmentScope = $Matches.Scope

function Get-PolicyScopeDetails {
    param([string] $Id)

    if ($Id -match '^/providers/Microsoft\.Management/managementGroups/(?<ManagementGroupName>[^/]+)$') {
        return @{ Type = 'ManagementGroup'; ManagementGroupName = $Matches.ManagementGroupName }
    }
    if ($Id -match '^/subscriptions/(?<SubscriptionId>[^/]+)$') {
        return @{ Type = 'Subscription'; SubscriptionId = $Matches.SubscriptionId }
    }
    if ($Id -match '^/subscriptions/(?<SubscriptionId>[^/]+)/resourceGroups/(?<ResourceGroupName>[^/]+)$') {
        return @{ Type = 'ResourceGroup'; SubscriptionId = $Matches.SubscriptionId; ResourceGroupName = $Matches.ResourceGroupName }
    }
    if ($Id -match '^/subscriptions/(?<SubscriptionId>[^/]+)(?:/resourceGroups/[^/]+)?/providers/[^/]+/[^/]+/[^/]+(?:/[^/]+/[^/]+)*$') {
        return @{ Type = 'Resource'; SubscriptionId = $Matches.SubscriptionId }
    }
    throw "Unsupported scope ID '$Id'. Use a full management group, subscription, resource group, or resource ID."
}

$assignmentDetails = Get-PolicyScopeDetails -Id $assignmentScope
$hasScope = $PSBoundParameters.ContainsKey('Scope')
$hasScopeId = $PSBoundParameters.ContainsKey('ScopeId')
if ($hasScope -ne $hasScopeId) {
    throw 'Specify both Scope and ScopeId, or omit both to use the assignment scope.'
}
$targetScope = $assignmentScope
if ($hasScopeId) {
    $targetScope = $ScopeId.Trim().TrimEnd('/')
}
$targetDetails = Get-PolicyScopeDetails -Id $targetScope
if ($hasScope -and $targetDetails.Type -ne $Scope) {
    throw "Scope '$Scope' does not match ScopeId '$targetScope' (type '$($targetDetails.Type)')."
}
if ($assignmentDetails.Type -ne 'ManagementGroup' -and
    -not $targetScope.Equals($assignmentScope, [System.StringComparison]::OrdinalIgnoreCase) -and
    -not $targetScope.StartsWith("$assignmentScope/", [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'ScopeId must be the assignment scope or a narrower scope within it.'
}

$requiredModules = @('Az.Accounts', 'Az.Resources', 'Az.PolicyInsights')
if ($StartStopVMs -eq 'YES') {
    $requiredModules += 'Az.Compute'
}
foreach ($moduleName in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $moduleName)) {
        throw "Missing module '$moduleName'. Install prerequisites with: Install-Module $($requiredModules -join ', ') -Scope CurrentUser"
    }
    Import-Module $moduleName -ErrorAction Stop
}

$loginParameters = @{
    Tenant = $TenantId
    Scope = 'Process'
    ErrorAction = 'Stop'
    WhatIf = $false
}
if ($targetDetails.SubscriptionId) {
    $loginParameters.Subscription = $targetDetails.SubscriptionId
}

Write-Host "Signing in to Azure tenant '$TenantId'..."
Connect-AzAccount @loginParameters | Out-Null

# Reading the assignment also verifies that it exists and is accessible.
$null = Get-AzPolicyAssignment -Id $PolicyAssignmentId -ErrorAction Stop

Write-Host "Reading recorded non-compliant resources for the assignment at scope '$targetScope'..."
$escapedAssignmentId = $PolicyAssignmentId.Replace("'", "''")
$stateParameters = @{
    All = $true
    Filter = "ComplianceState eq 'NonCompliant' and PolicyAssignmentId eq '$escapedAssignmentId'"
    Select = 'ResourceId,PolicyDefinitionAction,PolicyDefinitionReferenceId'
    ErrorAction = 'Stop'
}
switch ($targetDetails.Type) {
    'ManagementGroup' {
        $stateParameters.ManagementGroupName = $targetDetails.ManagementGroupName
    }
    'Subscription' {
        $stateParameters.SubscriptionId = $targetDetails.SubscriptionId
    }
    'ResourceGroup' {
        $stateParameters.SubscriptionId = $targetDetails.SubscriptionId
        $stateParameters.ResourceGroupName = $targetDetails.ResourceGroupName
    }
    'Resource' {
        $stateParameters.ResourceId = $targetScope
    }
}
if ((Get-Command Get-AzPolicyState).Parameters.ContainsKey('WhatIf')) {
    $stateParameters.WhatIf = $false
}
$states = @(Get-AzPolicyState @stateParameters)

if ($states.Count -eq 0) {
    Write-Warning 'No recorded non-compliant resources were found for this assignment at the target scope. Verify that the assignment applies there. This is not a fresh compliance scan; if changes are recent, wait for policy evaluation and rerun.'
    return
}

$eligibleStates = @($states | Where-Object {
    $_.PolicyDefinitionAction -in @('deployIfNotExists', 'modify')
})
$unsupportedCount = $states.Count - $eligibleStates.Count
if ($unsupportedCount -gt 0) {
    Write-Warning "$unsupportedCount non-compliant policy state(s) have effects that do not support remediation and will be skipped."
}
if ($eligibleStates.Count -eq 0) {
    Write-Warning 'No non-compliant resources have a deployIfNotExists or modify effect. No remediation tasks will be created.'
    return
}

$groups = @($eligibleStates | Group-Object -Property PolicyDefinitionReferenceId)

# Check every group before submitting anything, rather than silently truncating.
$approvedRemediations = @()
foreach ($group in $groups) {
    $resourceCount = @($group.Group.ResourceId | Sort-Object -Unique).Count
    if ($resourceCount -gt 50000) {
        throw "Policy reference '$($group.Name)' has $resourceCount resources. Azure allows at most 50,000 per remediation task. No tasks have been submitted; split remediation into smaller scopes."
    }
}

foreach ($group in $groups) {
    $resourceCount = @($group.Group.ResourceId | Sort-Object -Unique).Count
    $referenceId = [string] $group.Name
    $name = 'remediate-{0}-{1}' -f (Get-Date -Format 'yyyyMMddHHmmss'), ([guid]::NewGuid().ToString('N').Substring(0, 12))
    $remediationParameters = @{
        Name = $name
        Scope = $targetScope
        PolicyAssignmentId = $PolicyAssignmentId
        ResourceDiscoveryMode = 'ExistingNonCompliant'
        ResourceCount = 50000
        ErrorAction = 'Stop'
    }
    if (-not [string]::IsNullOrWhiteSpace($referenceId)) {
        $remediationParameters.PolicyDefinitionReferenceId = $referenceId
    }

    $target = "$PolicyAssignmentId at scope '$targetScope' (reference '$referenceId', $resourceCount recorded resource(s))"
    $action = "Create and start remediation '$name'"
    if ($StartStopVMs -eq 'YES') {
        $action += ', temporarily start stopped/deallocated VMs, wait for completion, and restore VM power states'
    }
    if ($PSCmdlet.ShouldProcess($target, $action)) {
        if ($StartStopVMs -eq 'NO') {
            Write-Host "Submitting remediation '$name' at scope '$targetScope'..."
            Start-AzPolicyRemediation @remediationParameters -Confirm:$false
        }
        else {
            $approvedRemediations += @{
                Parameters = $remediationParameters
                ResourceIds = @($group.Group.ResourceId)
            }
        }
    }
}

if ($approvedRemediations.Count -eq 0) {
    return
}

function Get-RemediationVMPowerState {
    param([hashtable] $VM)

    $instance = Get-AzVM -ResourceGroupName $VM.ResourceGroupName -Name $VM.Name -Status -DefaultProfile $VM.Profile -ErrorAction Stop
    $powerStates = @($instance.Statuses | Where-Object { $_.Code -like 'PowerState/*' })
    if ($powerStates.Count -ne 1) {
        throw "Cannot determine power state for VM '$($VM.Id)'."
    }
    return $powerStates[0].Code
}

function Wait-RemediationVMPowerState {
    param([hashtable] $VM, [string] $ExpectedState)

    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        if ((Get-RemediationVMPowerState -VM $VM) -eq $ExpectedState) {
            return
        }
        Start-Sleep -Seconds 15
    }
    throw "VM '$($VM.Id)' did not reach '$ExpectedState' within 15 minutes."
}

$originalContext = Get-AzContext -ErrorAction Stop
$profiles = @{}
$vms = @()
$changedVMs = @()
$activeRemediationName = $null
$operationError = $null
$restoreErrors = @()
try {
    $vmIds = @($approvedRemediations.ResourceIds | Sort-Object -Unique | Where-Object {
        $_ -match '^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft\.Compute/virtualMachines/[^/]+$'
    })
    # Preflight every VM before changing any power state.
    foreach ($vmId in $vmIds) {
        $null = $vmId -match '^/subscriptions/(?<Subscription>[^/]+)/resourceGroups/(?<Group>[^/]+)/providers/Microsoft\.Compute/virtualMachines/(?<Name>[^/]+)$'
        $subscription = $Matches.Subscription
        $vm = @{
            Id = $vmId
            ResourceGroupName = $Matches.Group
            Name = $Matches.Name
        }
        if (-not $profiles.ContainsKey($subscription)) {
            $profiles[$subscription] = Set-AzContext -Subscription $subscription -Tenant $TenantId -Scope Process -WhatIf:$false -Confirm:$false -ErrorAction Stop
        }
        $vm.Profile = $profiles[$subscription]
        $vm.OriginalState = Get-RemediationVMPowerState -VM $vm
        if ($vm.OriginalState -notin @('PowerState/running', 'PowerState/stopped', 'PowerState/deallocated')) {
            throw "VM '$vmId' is in state '$($vm.OriginalState)'. Wait for a stable running, stopped, or deallocated state and retry."
        }
        Write-Host "VM '$vmId': original state '$($vm.OriginalState)'."
        $vms += $vm
    }
    $null = Set-AzContext -Context $originalContext -Scope Process -WhatIf:$false -Confirm:$false -ErrorAction Stop

    foreach ($vm in $vms) {
        if ($vm.OriginalState -ne 'PowerState/running') {
            # Track before starting so partial startup failures also trigger cleanup.
            $changedVMs += $vm
            Write-Host "Starting VM '$($vm.Id)'..."
            $null = Start-AzVM -ResourceGroupName $vm.ResourceGroupName -Name $vm.Name -DefaultProfile $vm.Profile -Confirm:$false -ErrorAction Stop
            Wait-RemediationVMPowerState -VM $vm -ExpectedState 'PowerState/running'
        }
    }

    foreach ($remediation in $approvedRemediations) {
        $parameters = $remediation.Parameters
        # A submission error can be ambiguous: Azure might have accepted the task.
        $activeRemediationName = $parameters.Name
        Write-Host "Submitting remediation '$activeRemediationName' at scope '$targetScope'..."
        $null = Start-AzPolicyRemediation @parameters -Confirm:$false
        do {
            $result = Get-AzPolicyRemediation -Name $activeRemediationName -Scope $targetScope -ErrorAction Stop
            if ($null -eq $result -or [string]::IsNullOrWhiteSpace($result.ProvisioningState)) {
                throw "No remediation status was returned for '$activeRemediationName'."
            }
            Write-Host "Remediation '$activeRemediationName': $($result.ProvisioningState)."
            $isTerminal = $result.ProvisioningState -in @('Succeeded', 'Failed', 'Canceled', 'Cancelled')
            if (-not $isTerminal) {
                Start-Sleep -Seconds 15
            }
        } until ($isTerminal)
        $activeRemediationName = $null
        $result
        if ($result.ProvisioningState -ne 'Succeeded') {
            throw "Remediation '$($parameters.Name)' finished with state '$($result.ProvisioningState)'. Inspect its deployment errors in Azure Policy."
        }
    }
}
catch {
    $operationError = $_
}
finally {
    if ($activeRemediationName -and $changedVMs.Count -gt 0) {
        Write-Warning "Remediation '$activeRemediationName' at '$targetScope' may still be running. VMs will NOT be stopped while deployments may be active. After checking the task, restore these VMs manually:"
        foreach ($vm in $changedVMs) {
            Write-Warning "$($vm.Id): original state '$($vm.OriginalState)'."
        }
    }
    else {
        foreach ($vm in $changedVMs) {
            try {
                Write-Host "Restoring VM '$($vm.Id)' to '$($vm.OriginalState)'..."
                $stopParameters = @{
                    ResourceGroupName = $vm.ResourceGroupName
                    Name = $vm.Name
                    DefaultProfile = $vm.Profile
                    Force = $true
                    Confirm = $false
                    ErrorAction = 'Stop'
                }
                if ($vm.OriginalState -eq 'PowerState/stopped') {
                    $stopParameters.StayProvisioned = $true
                }
                $null = Stop-AzVM @stopParameters
                Wait-RemediationVMPowerState -VM $vm -ExpectedState $vm.OriginalState
            }
            catch {
                $restoreErrors += "VM '$($vm.Id)' could not be restored to '$($vm.OriginalState)': $_"
                Write-Warning $restoreErrors[-1]
            }
        }
    }
    try {
        $null = Set-AzContext -Context $originalContext -Scope Process -WhatIf:$false -Confirm:$false -ErrorAction Stop
    }
    catch {
        $restoreErrors += "Could not restore the original Azure context: $_"
        Write-Warning $restoreErrors[-1]
    }
}
if ($operationError) {
    throw $operationError
}
if ($restoreErrors.Count -gt 0) {
    throw ($restoreErrors -join [Environment]::NewLine)
}
