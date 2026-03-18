# T1087.001-8: Local Account — Enumerate all accounts on Windows (Local)

## Technique Context

T1087.001 represents Local Account Discovery, a fundamental reconnaissance technique where adversaries enumerate user accounts on the local system to understand the security landscape and identify potential targets for privilege escalation or lateral movement. This technique is particularly valuable early in an attack chain, as it reveals administrator accounts, service accounts, and standard users that may be targeted for credential harvesting or account takeover. Detection engineers focus on identifying suspicious enumeration patterns, especially when combined with other discovery activities, as legitimate administrative tasks typically follow predictable patterns while adversarial reconnaissance often involves broad, systematic enumeration across multiple information sources.

## What This Dataset Contains

This dataset captures a comprehensive local account enumeration sequence executed through PowerShell and native Windows commands. The execution chain begins with PowerShell (PID 20796) spawning `cmd.exe` with the command line `"cmd.exe" /c net user & dir c:\Users\ & cmdkey.exe /list & net localgroup "Users" & net localgroup`, clearly demonstrating systematic information gathering.

The enumeration sequence includes:
- `net user` execution to list all local user accounts (Security 4688, Sysmon 1)  
- `cmdkey.exe /list` to enumerate stored credentials (Security 4688, Sysmon 1)
- `net localgroup "Users"` to list members of the Users group (Security 4688, Sysmon 1)
- `net localgroup` to enumerate all local groups (Security 4688, Sysmon 1)
- A `dir c:\Users\` command to enumerate user profile directories
- A preceding `whoami.exe` execution for current user context discovery

Each net.exe execution spawns its corresponding net1.exe worker process, creating the complete process chain: `powershell.exe → cmd.exe → net.exe → net1.exe`. The Sysmon events properly tag these processes with technique IDs including T1087.001 (Local Account), T1087 (Account Discovery), T1018 (Remote System Discovery), and T1033 (System Owner/User Discovery).

Security event 4703 captures token privilege adjustment for the PowerShell process, showing elevation of multiple high-privilege rights including SeBackupPrivilege and SeRestorePrivilege.

## What This Dataset Does Not Contain

The dataset lacks the actual command output that would show the discovered accounts and groups, as Windows event logging captures process execution but not stdout/stderr. The `dir c:\Users\` command execution is not visible in Sysmon events due to the include-mode filtering configuration that only captures suspicious processes, and `dir` is implemented as a cmd.exe internal command rather than a separate executable.

No registry access events are present, which would typically accompany more sophisticated enumeration techniques that directly query SAM database entries. The dataset also doesn't contain any follow-on activities that might leverage the discovered account information, such as credential access attempts or privilege escalation activities.

## Assessment

This dataset provides excellent telemetry for detecting local account enumeration activities. The Security 4688 events with command-line logging capture the exact enumeration commands, while Sysmon events add process relationships and technique tagging that significantly enhance detection capabilities. The combination of multiple enumeration techniques in a single command chain creates a strong behavioral signature that would be difficult for attackers to avoid while maintaining effectiveness.

The process genealogy tracking through both Security and Sysmon events allows detection engineers to build robust rules that identify enumeration sequences regardless of the specific tools used. The privilege adjustment event (4703) adds an additional detection dimension for identifying processes that might be preparing for more advanced post-enumeration activities.

## Detection Opportunities Present in This Data

1. **Multi-command enumeration sequence detection** - Alert on cmd.exe executing multiple account discovery commands within a short time window using the chained command pattern `net user & dir c:\Users\ & cmdkey.exe /list & net localgroup`

2. **Native binary account enumeration clustering** - Detect rapid succession of net.exe, cmdkey.exe, and whoami.exe executions from the same parent process, particularly when combined with directory enumeration

3. **PowerShell-initiated discovery chain** - Monitor for PowerShell spawning cmd.exe processes that subsequently execute multiple account discovery utilities

4. **Token privilege escalation preceding enumeration** - Correlate Security 4703 privilege adjustment events with subsequent account discovery activities to identify potentially malicious reconnaissance

5. **Net command enumeration pattern** - Alert on net.exe processes with user, localgroup, or group parameters, especially when multiple variations occur in sequence

6. **Process ancestry anomaly detection** - Flag unusual parent-child relationships where interactive shells spawn systematic enumeration tools outside of expected administrative contexts
