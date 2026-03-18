# T1087.002-7: Domain Account — Adfind - Enumerate Active Directory User Objects

## Technique Context

T1087.002 focuses on domain account discovery, where adversaries enumerate user accounts in Active Directory to understand the domain structure, identify high-value targets, and plan lateral movement. AdFind is a legitimate Active Directory query tool frequently abused by threat actors for reconnaissance activities. The detection community particularly focuses on monitoring for LDAP queries targeting user objects, process execution of known AD enumeration tools, and command-line patterns that indicate systematic account discovery. This technique is commonly seen in the early stages of domain compromise and is often followed by credential harvesting and privilege escalation attempts.

## What This Dataset Contains

This dataset captures a failed AdFind execution attempt where the tool appears to have encountered an error. The key telemetry includes:

**Process Creation Chain:**
- Security 4688: PowerShell parent process spawning cmd.exe with command line `"cmd.exe" /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\AdFind.exe" -f (objectcategory=person)`
- Security 4688: cmd.exe exit with status 0x1 (indicating failure)
- Sysmon 1: cmd.exe process creation with the AdFind command line parameters

**Process Monitoring:**
- Sysmon 10: Two process access events showing PowerShell accessing both whoami.exe and cmd.exe with full access rights (0x1FFFFF)
- Security 4689: Multiple process termination events for whoami, cmd.exe, and PowerShell processes

**Supporting Activity:**
- Extensive PowerShell .NET framework DLL loading events (Sysmon 7) including System.Management.Automation
- PowerShell named pipe creation for inter-process communication
- File creation events for PowerShell startup profile data

The PowerShell channel contains only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) with no technique-specific script content captured.

## What This Dataset Does Not Contain

The dataset lacks the actual AdFind.exe process creation event, which suggests the tool either failed to execute properly or was blocked by security controls. The cmd.exe process exits with status 0x1, indicating an execution failure rather than successful enumeration. There are no network connection events (Sysmon 3) showing LDAP queries to domain controllers, no successful LDAP query results, and no evidence of Active Directory object enumeration completing. The Sysmon configuration's include-mode filtering for ProcessCreate events likely excluded the AdFind.exe execution since it's not matching the predefined suspicious process patterns.

## Assessment

This dataset provides moderate value for detection engineering focused on identifying *attempts* to use AdFind for domain enumeration, even when those attempts fail. The command-line detection opportunities are strong, with clear evidence of AdFind being invoked with AD enumeration parameters. However, the dataset's utility for understanding successful enumeration behaviors is limited due to the apparent execution failure. The process access events and parent-child relationship telemetry are valuable for behavioral detection, but the lack of network activity and actual LDAP query evidence reduces its completeness for comprehensive AD enumeration detection development.

## Detection Opportunities Present in This Data

1. **Command-line pattern detection** - Monitor for "AdFind.exe" combined with LDAP filter parameters like "-f (objectcategory=person)" in process command lines

2. **Process execution chain analysis** - Detect PowerShell spawning cmd.exe which attempts to execute AdFind.exe from non-standard locations like "ExternalPayloads" directories

3. **Known AD enumeration tool detection** - Alert on execution attempts of AdFind.exe regardless of success status, particularly when invoked with common reconnaissance parameters

4. **Process access pattern monitoring** - PowerShell accessing cmd.exe with full privileges (0x1FFFFF) followed by immediate process termination may indicate failed tool execution

5. **Parent-child process relationship tracking** - PowerShell → cmd.exe → AdFind.exe execution chains, especially when originating from automated frameworks or unusual working directories

6. **File path analysis** - Monitor for execution attempts from "AtomicRedTeam" or "ExternalPayloads" directory structures which may indicate testing or attack tool staging
