# T1018-17: Remote System Discovery — Enumerate Active Directory Computers with Get-AdComputer

## Technique Context

T1018 Remote System Discovery encompasses methods adversaries use to enumerate remote systems and services in their environment. The `Get-AdComputer` cmdlet represents a particularly powerful Active Directory enumeration technique that allows attackers to discover all computer objects in the domain, providing critical reconnaissance data for lateral movement planning. Unlike network scanning or ping sweeps, this technique leverages legitimate Active Directory queries through LDAP, making it stealthy and difficult to distinguish from normal administrative activity. Security teams focus on detecting unusual PowerShell usage patterns, AD query anomalies, and correlating discovery activities with other attack phases.

## What This Dataset Contains

This dataset captures a successful execution of `Get-AdComputer -Filter *` through PowerShell, generating substantial telemetry across multiple channels. The Security channel shows the key process creation in EID 4688: `"powershell.exe" & {Get-AdComputer -Filter *}` with ProcessId 0x488. The PowerShell channel captures the actual command execution in two script block logs (EIDs 4104): `& {Get-AdComputer -Filter *}` and `{Get-AdComputer -Filter *}` with script block IDs 8c0dbc39-3152-4930-8711-b444c0ac68dd and b4e7186c-6c08-4205-9763-8ccebd28e2ea respectively.

Sysmon provides rich process telemetry including the PowerShell process creation (EID 1) showing `CommandLine: "powershell.exe" & {Get-AdComputer -Filter *}` and extensive DLL loading events showing .NET runtime initialization and PowerShell module loading. The technique executes successfully as evidenced by normal process exit codes (0x0) in Security EID 4689 events, indicating the AD query completed without errors.

The execution involves two PowerShell processes - the parent test framework process (PID 5760) and the child process (PID 1160) that actually executes the Get-AdComputer command. Process access events (Sysmon EID 10) show the parent process accessing both whoami.exe and the child PowerShell process with full access rights (0x1FFFFF).

## What This Dataset Does Not Contain

The dataset lacks the actual output of the Get-AdComputer command - we see the command execution but not the enumerated computer objects that would be returned. There are no network connection events (Sysmon EID 3) showing the LDAP queries to domain controllers, which would typically be present during AD enumeration. The dataset also doesn't contain any Windows event logs from the domain controller side that would show the LDAP query requests.

DNS query events (Sysmon EID 22) are absent, which might appear if the system needed to resolve domain controller names. The technique completed successfully without Windows Defender intervention, as evidenced by the clean exit codes and lack of error events.

## Assessment

This dataset provides excellent telemetry for detecting PowerShell-based Active Directory enumeration. The combination of Security 4688 process creation with command-line logging and PowerShell 4104 script block logging creates multiple detection points that are difficult for attackers to evade simultaneously. The Sysmon process creation and DLL loading events add additional context about the execution environment.

The data quality is strong for building detections focused on command-line patterns, PowerShell usage, and process relationships. However, the absence of network telemetry limits visibility into the actual AD communication, which could be valuable for network-based detection strategies.

## Detection Opportunities Present in This Data

1. **PowerShell Get-AdComputer command detection** - Security EID 4688 and PowerShell EID 4104 both capture `Get-AdComputer -Filter *` execution with clear command-line evidence

2. **PowerShell script block analysis** - PowerShell EID 4104 events contain the exact AD enumeration commands in script block text, enabling content-based detection

3. **Process ancestry analysis** - Sysmon EID 1 shows PowerShell spawning from another PowerShell process, indicating potential scripted execution of reconnaissance commands

4. **Privilege escalation context** - Security EID 4703 shows token right adjustment with extensive privileges (SeBackupPrivilege, SeRestorePrivilege, etc.) correlating with AD enumeration

5. **PowerShell module loading patterns** - Sysmon EID 7 events show System.Management.Automation.dll loading, indicating PowerShell cmdlet execution that could correlate with AD enumeration

6. **Process access correlation** - Sysmon EID 10 events show the PowerShell process accessing other processes with full rights, which could indicate enumeration-related process interaction
