# T1531-3: Account Access Removal — Remove Account From Domain Admin Group

## Technique Context

T1531 at domain scope is considerably more impactful than local account manipulation: stripping a user from Domain Admins removes enterprise-wide administrative access in a single operation. Adversaries use this before deploying ransomware to prevent domain admins from halting the attack, or as sabotage to disrupt recovery. Detection teams focus on Security Event ID 4756 (member removed from a universal security group) and 4728/4732 (member removed from global/local security group) at the domain controller, as well as the PowerShell `Remove-ADGroupMember` cmdlet invocation and command-line evidence on workstations used as jump points.

## What This Dataset Contains

The test executes a PowerShell script block that attempts to remove a placeholder account (`remove_user`) from Domain Admins using the Active Directory module:

```powershell
$PWord = ConvertTo-SecureString -String password -AsPlainText -Force
$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList domain\super_user, $PWord
if((Get-ADUser remove_user -Properties memberof).memberof -like "CN=Domain Admins*"){
  Remove-ADGroupMember -Identity "Domain Admins" -Members remove_user -Credential $Credential -Confirm:$False
}
```

This script block is captured verbatim in PowerShell Event ID 4104 (Script Block Logging). Event ID 4103 (Module Logging) records `ConvertTo-SecureString` and `New-Object` with parameter bindings — notably, the plaintext credential string `password` is exposed in the `ConvertTo-SecureString` binding. Security 4688 captures the child `powershell.exe` spawned to run this block, with the full command line including the script. Sysmon Event ID 1 records the same with parent-child relationship: outer `powershell.exe` (ART test framework) → inner `powershell.exe` (technique script).

The test runs from a workstation (`ACME-WS02`) against `acme.local`. The `remove_user` account does not actually exist in the domain (this is a placeholder), so `Get-ADUser` would fail and `Remove-ADGroupMember` would not execute. No account management events appear here — those would be generated at the domain controller, not the workstation.

## What This Dataset Does Not Contain

**No domain controller telemetry.** The actual group membership change events (4728, 4732, 4756) are generated on the DC, not on the workstation where the command runs. This dataset covers only the workstation-side execution evidence.

**No account management events in the Security log.** The workstation audit policy sets `account_management: none`. Even if the command had succeeded, the local Security log would not reflect domain group membership changes.

**No successful execution.** The account `remove_user` does not exist in the domain, so `Get-ADUser` returns an error and the `Remove-ADGroupMember` call is never reached. The PowerShell module logging for `Remove-ADGroupMember` is absent for this reason.

**The credential `password` for `domain\super_user` appears in module logging** but is the placeholder value from the ART test — not a real credential.

## Assessment

This dataset is particularly valuable for PowerShell-focused detections. The script block and module logging provide complete visibility into the technique's intent: the AD group membership check, the credential construction, and the attempted `Remove-ADGroupMember`. The plaintext credential exposure in `ConvertTo-SecureString` module logging is a realistic detection opportunity for credential harvesting from logs. The dataset is honest about its scope: workstation-only telemetry, with no DC events and no successful execution. Pairing this with DC Security logs would complete the picture.

## Detection Opportunities Present in This Data

1. **PowerShell Event ID 4104**: Script block containing `Remove-ADGroupMember` — the most direct indicator of this sub-technique.
2. **PowerShell Event ID 4104**: Script block containing `ConvertTo-SecureString -AsPlainText` combined with an AD cmdlet — credential-in-script pattern.
3. **PowerShell Event ID 4103**: `ConvertTo-SecureString` with `name="String"` parameter binding exposing a plaintext value — credential in module logging.
4. **Security 4688**: `powershell.exe` spawned by `powershell.exe` with `Remove-ADGroupMember` in the command line — PowerShell-based AD manipulation.
5. **Sysmon Event ID 1**: `powershell.exe` child of `powershell.exe` with `Get-ADUser` and `memberof` and `Domain Admins` in CommandLine — group membership probing prior to modification.
6. **PowerShell Event ID 4104**: Script block containing both `Get-ADUser` and `Remove-ADGroupMember` in the same block — reconnaissance-then-action pattern for group membership manipulation.
