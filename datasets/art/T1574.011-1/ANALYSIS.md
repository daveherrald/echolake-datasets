# T1574.011-1: Services Registry Permissions Weakness — Services Registry Permissions Weakness - Service Registry Permissions Weakness

## Technique Context

T1574.011 (Hijack Execution Flow: Services Registry Permissions Weakness) exploits misconfigured permissions on service registry keys. When a non-privileged user has write access to a service's registry key under `HKLM\SYSTEM\CurrentControlSet\Services\`, they can modify the `ImagePath` value to point to an arbitrary executable. The next time the service starts — potentially under a privileged account — the attacker's binary runs with elevated privileges.

This test enumerates service registry key ACLs to identify weakly-permissioned services, specifically targeting `weakservicename`, and then queries the ACL for that service's key. The test focuses on the reconnaissance phase: discovering which services have exploitable permissions.

## What This Dataset Contains

The dataset captures 89 events across Sysmon (32), Security (10), and PowerShell (47) logs collected over approximately 10 seconds on ACME-WS02.

**The reconnaissance commands are fully logged:**

Sysmon Event 1 shows the attack script spawning a new PowerShell process:
- `"powershell.exe" & {get-acl REGISTRY::HKLM\SYSTEM\CurrentControlSet\Services\* |FL; get-acl REGISTRY::HKLM\SYSTEM\CurrentControlSet\Services\weakservicename |FL}`

Sysmon Event 10 (Process Access) shows:
- `powershell.exe` accessing `whoami.exe` — pre-attack identity confirmation
- `powershell.exe` self-accessing `powershell.exe` — the parent test framework spawning a child PowerShell for the test

PowerShell Event 4104 (Script Block Logging) captures the script block:
- `& {get-acl REGISTRY::HKLM\SYSTEM\CurrentControlSet\Services\* |FL; get-acl REGISTRY::HKLM\SYSTEM\CurrentControlSet\Services\weakservicename |FL}`

PowerShell Event 4103 (Module Logging) records:
- `CommandInvocation(Get-Acl): "Get-Acl"` with `path="REGISTRY::HKLM\SYSTEM\CurrentControlSet\Services\weakservicename"` and `CommandInvocation(Format-List): "Format-List"` — confirming the ACL enumeration executed.

Sysmon Event 11 (File Created) shows PowerShell startup profile data files written, which is normal PowerShell session initialization behavior.

**Note on event counts:** The source collection captured 24,831–26,704 PowerShell events but only 47 appear in the bundled dataset. This is because the test triggered extensive PowerShell pipeline processing for the `Get-Acl` enumeration of all services, most of which was filtered during the curated export.

## What This Dataset Does Not Contain (and Why)

**No registry modification.** This test only enumerates ACLs; it does not exploit any weakness found. No Sysmon Event 13 (registry value set) appears because no `ImagePath` was changed.

**No service execution.** No service was started or stopped. The attack stopped at the reconnaissance phase.

**No evidence of `weakservicename` existing.** If `weakservicename` does not exist on the test system, `Get-Acl` would return an error rather than useful output. The PowerShell module log shows the command was invoked, but no output indicating a discovered weak service is present in the bundled data.

**Sysmon Event 1 does not capture the child PowerShell fully.** The Sysmon include filter captures `powershell.exe` child processes when the parent command line matches, which it did here. However, the full ACL output is only visible in PowerShell script block logs, not in Sysmon.

**High PowerShell event volume at source.** The 24,000+ PowerShell events at source reflect `Get-Acl` enumerating potentially hundreds of service keys, each generating pipeline and formatting events. The curated dataset retains only the attack-relevant script block captures.

## Assessment

This dataset captures the reconnaissance phase of a Services Registry Permissions Weakness attack — specifically, ACL enumeration of all service registry keys. The PowerShell script block and module logging provide clear visibility into what was queried. This is a useful dataset for training detections against `Get-Acl` used against the services registry hive, which has a narrow legitimate use case and is a common precursor to registry-based service persistence.

## Detection Opportunities Present in This Data

- **PowerShell Event 4104**: Script block containing `get-acl REGISTRY::HKLM\SYSTEM\CurrentControlSet\Services\*` — bulk ACL enumeration of the services hive is a recon indicator.
- **PowerShell Event 4103**: `Get-Acl` invocation against `REGISTRY::HKLM\SYSTEM\CurrentControlSet\Services\weakservicename` — targeted ACL query on a specific named service.
- **Sysmon Event 1**: `powershell.exe` spawning a child `powershell.exe` with a registry ACL enumeration block inline — PowerShell spawning PowerShell with a registry query payload is suspicious.
- **Sysmon Event 10**: `powershell.exe` accessing `powershell.exe` — parent-child PowerShell process access relationship warrants review.
- **Security Event 4688**: Child `powershell.exe` created with the ACL enumeration command in the process command line — Security log provides complementary coverage to Sysmon for this process.
- **PowerShell Event 4103**: `Set-ExecutionPolicy -Scope Process -Force` — ART test framework initialization; its presence in logs indicates a scripted execution context.
