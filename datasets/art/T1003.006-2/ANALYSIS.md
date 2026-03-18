# T1003.006-2: DCSync — Run DSInternals Get-ADReplAccount

## Technique Context

DCSync is a powerful credential harvesting technique that exploits Active Directory replication protocols to extract password data from domain controllers without requiring LSASS access. Attackers use legitimate AD replication APIs (like DsGetNCChanges) to request password hashes, Kerberos keys, and other credential material for any domain account. The technique is particularly dangerous because it appears as normal DC-to-DC replication traffic and requires only the "Replicating Directory Changes" and "Replicating Directory Changes All" permissions.

Detection engineers focus on monitoring for DCSync activity through multiple vectors: unusual replication requests from non-DC systems, PowerShell modules like DSInternals that implement DCSync functionality, and network traffic patterns associated with directory replication APIs. The DSInternals PowerShell module's Get-ADReplAccount cmdlet is a commonly observed tool in post-exploitation scenarios, making PowerShell script block logging crucial for detecting this attack path.

## What This Dataset Contains

This dataset captures an attempted DCSync attack using the DSInternals PowerShell module. The key evidence appears in Security event 4688 showing PowerShell execution with the command line `"powershell.exe" & {Get-ADReplAccount -All -Server $ENV:logonserver.TrimStart(\"\\\")}"`. The PowerShell channel contains the critical script block in event 4104: `Get-ADReplAccount -All -Server $ENV:logonserver.TrimStart("\")` and `{Get-ADReplAccount -All -Server $ENV:logonserver.TrimStart("\")}`.

The process chain shows the parent PowerShell process (PID 1396) spawning a child PowerShell process (PID 6296) to execute the DCSync command. Sysmon captures both processes in event ID 1, with the child process showing the full DCSync command line. The dataset includes comprehensive DLL loading events (Sysmon EID 7) showing .NET runtime initialization and PowerShell module loading, plus process access events (Sysmon EID 10) indicating inter-process communication.

Security event 4703 shows privilege adjustments including SeBackupPrivilege and SeRestorePrivilege, which are commonly associated with credential access operations. The execution completes successfully with exit code 0x0 across all processes.

## What This Dataset Does Not Contain

This dataset lacks the most critical telemetry for DCSync detection: network traffic showing actual AD replication requests. There are no network connection events (Sysmon EID 3) documenting LDAP/RPC connections to domain controllers, and no Kerberos authentication events (Security EID 4768/4769) showing the service ticket requests typically required for DCSync operations.

The PowerShell script block logging captures the command execution but doesn't show the actual output or success/failure of the Get-ADReplAccount operation. Missing are any file creation events that might indicate credential dumps being written to disk, and there's no evidence of the DSInternals module being imported or installed on the system.

Windows event logs don't contain the domain controller perspective of this attack - events like Security 4662 (directory service access) with replication GUIDs that would appear on the target DC are absent since this is workstation-only telemetry.

## Assessment

This dataset provides solid evidence of DCSync technique execution from a process and command-line perspective. The PowerShell script block logging captures the exact DSInternals command being executed, while Security 4688 events provide reliable command-line auditing. The comprehensive Sysmon process creation and DLL loading events support attribution and process tree analysis.

However, the dataset's utility is limited by the absence of network telemetry, which is often the most reliable way to detect DCSync in enterprise environments. The lack of domain controller logs also prevents analysis of the attack from the target perspective. For building DCSync detections, this data is most valuable for identifying PowerShell-based tooling usage rather than detecting the underlying replication abuse.

## Detection Opportunities Present in This Data

1. **PowerShell Script Block Detection** - Monitor PowerShell EID 4104 for "Get-ADReplAccount" cmdlet execution, particularly with "-All" parameter indicating bulk credential harvesting attempts.

2. **Command Line Analysis** - Detect Security EID 4688 process creation events with command lines containing "Get-ADReplAccount", "DSInternals", or AD replication-related PowerShell cmdlets.

3. **Process Tree Analysis** - Identify PowerShell parent-child relationships where the child process executes DCSync-related commands, using Sysmon EID 1 process creation events with parent process correlation.

4. **Privilege Escalation Correlation** - Correlate Security EID 4703 privilege adjustment events (especially SeBackupPrivilege/SeRestorePrivilege) with subsequent PowerShell execution of credential access tools.

5. **PowerShell Module Loading** - Monitor Sysmon EID 7 image load events for System.Management.Automation.dll in conjunction with suspicious PowerShell command execution.

6. **Execution Policy Bypass** - Detect PowerShell EID 4103 showing "Set-ExecutionPolicy Bypass" immediately preceding credential access operations as potential attack preparation.
