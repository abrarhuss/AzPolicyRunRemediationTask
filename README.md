# Azure Policy assignment remediation

[Start-PolicyRemediationTask.ps1](./Start-PolicyRemediationTask.ps1) signs in
interactively to the specified Azure tenant and creates and starts remediation
tasks for a policy assignment's recorded non-compliant resources.
It supports policy and initiative assignments at management group, subscription,
resource group, and individual resource scopes. By default, the remediation scope
is taken from the assignment ID. Use `-Scope` and `-ScopeId` together to target
that scope or a narrower scope where the assignment is inherited.

## Prerequisites

- PowerShell 5.1 or later.
- Install the Azure PowerShell modules once:

  ```powershell
  Install-Module Az.Accounts, Az.Resources, Az.PolicyInsights -Scope CurrentUser
  ```

- The signed-in user needs permission to read the assignment and policy states
  and create remediation tasks at the target scope. Resource Policy
  Contributor is a typical role for managing remediation.
- The assignment must already have a managed identity with the roles required
  by its policies on the target resources. This script does not grant roles or
  create an identity.

## Run

```powershell
.\Start-PolicyRemediationTask.ps1 `
    -TenantId '00000000-0000-0000-0000-000000000000' `
    -PolicyAssignmentId '/subscriptions/11111111-1111-1111-1111-111111111111/providers/Microsoft.Authorization/policyAssignments/my-assignment'
```

Use the **full assignment resource ID**, available on the policy assignment's
Properties page in Azure Portal. The script authenticates Azure PowerShell;
it does not automate the portal UI. For subscription-based targets, login
selects the subscription from the target scope ID.

### Select a target scope

Supply both `-Scope` and `-ScopeId`, or omit both to retain the assignment scope.
`-ScopeId` must be a full Azure resource ID, not a name.

| `-Scope` | `-ScopeId` format |
|---|---|
| `ManagementGroup` | `/providers/Microsoft.Management/managementGroups/<management-group-id>` |
| `Subscription` | `/subscriptions/<subscription-id>` |
| `ResourceGroup` | `/subscriptions/<subscription-id>/resourceGroups/<resource-group-name>` |
| `Resource` | `/subscriptions/<subscription-id>/resourceGroups/<resource-group-name>/providers/<namespace>/<resource-type>/<resource-name>` |

For example, remediate a subscription assignment in just one resource group:

```powershell
.\Start-PolicyRemediationTask.ps1 `
    -TenantId '00000000-0000-0000-0000-000000000000' `
    -PolicyAssignmentId '/subscriptions/11111111-1111-1111-1111-111111111111/providers/Microsoft.Authorization/policyAssignments/my-assignment' `
    -Scope ResourceGroup `
    -ScopeId '/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/my-resource-group' `
    -WhatIf
```

The scope type must match the ID. Subscription, resource group, and resource
assignments cannot target a scope outside their assignment scope. For management
group assignments, ensure the target is in that management group's hierarchy;
the script does not resolve management group ancestry. Only recorded states for
the specified assignment at the target scope are considered.

Sign-in uses the standard interactive Azure authentication flow, not device-code authentication.
Add `-WhatIf` to preview task creation without submitting remediations.
Preview still signs in and reads Azure data. Add `-Confirm` to approve each task.

### Temporarily start non-compliant VMs

For policies that need a running VM (for example, VM extension deployments), use:

```powershell
.\Start-PolicyRemediationTask.ps1 `
    -TenantId '<tenant-id>' `
    -PolicyAssignmentId '<full-assignment-resource-id>' `
    -StartStopVMs YES
```

- `-StartStopVMs` accepts `YES` or `NO` (default). `NO` preserves the original
  submit-only behavior and does not read or change VM power states.
- `YES` also requires `Az.Compute`: `Install-Module Az.Compute -Scope CurrentUser`.
  The signed-in user needs permission to read, start, power off, and deallocate
  VMs in every affected subscription (for example, Virtual Machine Contributor).
- Only unique `Microsoft.Compute/virtualMachines` resources in eligible,
  approved non-compliant policy states are considered. Other resource types,
  including VM scale sets and VM child resources, are not started.
- All VM power states are checked before starting any VM. Running VMs are left
  alone; stopped and deallocated VMs are started and checked for a running state
  before submitting remediation. Unknown or transitional states stop execution
  before any VMs are started; wait for a stable state and retry.
- Tasks are submitted sequentially and polled every 15 seconds until they
  succeed, fail, or are canceled. Keep PowerShell open. There is no remediation
  timeout: VMs must remain running while deployments are active.
- After completion, including a failed/canceled task or a VM startup failure,
  cleanup attempts to restore every VM whose startup was attempted.
  Originally deallocated VMs are deallocated again; originally stopped VMs
  are powered off with `-StayProvisioned` (still allocated). Each VM transition
  is checked for up to 15 minutes. Restoration failures are reported, and
  cleanup continues for the remaining VMs. The original Azure context is restored.
- If submission or status monitoring fails, a task may still be running.
  In that case, VMs are deliberately left running rather than interrupting
  deployments. Warnings list their IDs and original states for manual restoration
  after checking the task. Closing/killing PowerShell can also prevent cleanup;
  this is not a durable recovery service.
- `-WhatIf` previews the combined remediation/start/restore action without
  changing VMs or submitting tasks. `-Confirm` approves each combined action
  before any VM changes. Temporarily running VMs incurs compute costs and may
  change dynamic IP addresses; restoration covers power state only.

## Behavior and limitations

- Only `deployIfNotExists` and `modify` effects can be remediated automatically.
  Other non-compliant states are reported as skipped; audit and deny findings
  cannot be fixed with a remediation task.
- An initiative requires a separate task for each eligible policy definition
  reference. All eligible references found in the recorded states are processed.
- This uses existing compliance results, not a fresh scan. For recent changes,
  trigger a compliance evaluation in Azure and wait for updated results before
  running the script. No results does not prove compliance.
- Compliance queries and remediation tasks use the selected management group,
  subscription, resource group, or resource scope and filter by the full
  assignment ID. Management group queries use `-ManagementGroupName`, not
  the unsupported `Get-AzPolicyState -ResourceId` assignment endpoint.
- Each task explicitly requests the Azure maximum of **50,000 resources**, not
  the default 500. If a reference already has more than 50,000 recorded resources,
  the script stops before creating any tasks. Split remediation into smaller
  scopes in that case. Azure discovers eligible resources when a task runs, so
  changes after the query can affect the set processed.
- Remediation can change resources and deploy billable services. Review policy
  definitions and preview before executing in production.
- Task objects are returned by `Start-AzPolicyRemediation`. Submission is not
  proof of successful remediation. Monitor progress and deployment failures in
  **Azure Portal > Policy > Remediation**, or use `Get-AzPolicyRemediation`.
  Compliance results may take additional time to update.
  With `-StartStopVMs YES`, the script instead waits and returns the final
  `Get-AzPolicyRemediation` objects, and reports failed/canceled tasks as errors.
- Azure errors stop execution. Tasks submitted before an error are not rolled
  back; inspect them before retrying.

## Tests

Run the self-contained regression tests on PowerShell 5.1 or later:

```powershell
.\Tests\Start-PolicyRemediationTask.Tests.ps1
```

The tests mock Azure commands: they do not sign in, start VMs, or submit real
remediation tasks.

## References

- [Start-AzPolicyRemediation](https://learn.microsoft.com/powershell/module/az.policyinsights/start-azpolicyremediation)
- [Azure remediation task structure and limits](https://learn.microsoft.com/azure/governance/policy/concepts/remediation-structure)
