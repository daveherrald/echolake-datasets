# T1222.001-6: Windows File and Directory Permissions Modification — SubInAcl Execution

## Technique Context

T1222.001 represents Windows File and Directory Permissions Modification, a defense evasion technique where attackers modify NTFS permissions or ownership to evade security controls, persist access, or escalate privileges. Attackers commonly use built-in utilities like `icacls`, `cacls`, `takeown`, or third-party tools like `subinacl` to manipulate ACLs on sensitive files, directories, or registry keys. This technique often precedes credential theft, persistence mechanisms, or privilege escalation attempts.

The detection community focuses on monitoring command-line execution of permission modification tools, especially when targeting security-sensitive locations like system directories, security databases, or authentication-related files. Unusual permission changes by non-administrative processes or modifications to critical system resources are key indicators of malicious activity.

## What This Dataset Contains

This dataset captures an execution attempt of `subinacl.exe` through PowerShell that ultimately fails. The key telemetry includes:

Security events show the command execution through cmd.exe: `"cmd.exe" /c "C:\Program Files (x86)\Windows Resource Kits\Tools\subinacl.exe"` (EID 4688). The cmd.exe process exits with status 0x1 (EID 4689), indicating failure.

Sysmon EID 1 captures the cmd.exe process creation with CommandLine: `"cmd.exe" /c "C:\Program Files (x86)\Windows Resource Kits\Tools\subinacl.exe"` spawned by powershell.exe (PID 37300).

Multiple process access events (Sysmon EID 10) show PowerShell accessing both whoami.exe and cmd.exe processes with full access rights (0x1FFFFF).

Token privilege adjustment (Security EID 4703) shows PowerShell enabling extensive system privileges including SeBackupPrivilege, SeRestorePrivilege, SeTakeOwnershipPrivilege, and SeSecurityPrivilege.

A preliminary whoami.exe execution occurs before the subinacl attempt, captured in both Security 4688 and Sysmon EID 1 events.

## What This Dataset Does Not Contain

The subinacl.exe process itself is not captured in Sysmon ProcessCreate events, likely because it failed to execute successfully (indicated by cmd.exe exit code 0x1) and the sysmon-modular configuration uses include-mode filtering that may not capture this specific executable.

No file or registry permission modifications are visible since the subinacl execution failed. There are no object access events showing actual ACL changes.

No network activity or file write operations related to the subinacl execution are present, consistent with the tool not running successfully.

The PowerShell channel contains only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) rather than the actual technique implementation commands.

## Assessment

This dataset provides moderate detection value despite the failed execution. The command-line evidence in Security 4688 events clearly shows the subinacl execution attempt with full command-line parameters. The privilege escalation telemetry (EID 4703) demonstrates the enabling of powerful system privileges that are prerequisites for permission modification operations.

The process access events and parent-child relationships provide good context for understanding the attack chain. However, the dataset would be stronger with a successful execution showing actual permission changes and the subinacl process creation itself.

## Detection Opportunities Present in This Data

1. **Command-line detection** - Monitor Security 4688 for cmd.exe executing subinacl.exe with specific command patterns: `cmd.exe /c *subinacl.exe*`

2. **Privilege escalation monitoring** - Alert on Security 4703 events where processes enable combinations of SeBackupPrivilege, SeRestorePrivilege, SeTakeOwnershipPrivilege, and SeSecurityPrivilege

3. **Process ancestry analysis** - Detect PowerShell spawning cmd.exe which attempts to execute permission modification tools like subinacl.exe

4. **Failed execution detection** - Monitor for cmd.exe processes with non-zero exit codes (0x1) when executing security-related tools, indicating blocked or failed attempts

5. **Suspicious process access** - Alert on PowerShell processes accessing system utilities (whoami.exe, cmd.exe) with full access rights (0x1FFFFF) as potential preparation for privilege abuse

6. **Tool presence verification** - Correlate subinacl execution attempts with actual file presence at expected paths like `C:\Program Files (x86)\Windows Resource Kits\Tools\subinacl.exe`
