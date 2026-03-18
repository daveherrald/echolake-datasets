# T1134.005-1: SID-History Injection — Injection SID-History with mimikatz

## Technique Context

SID-History Injection (T1134.005) is a privilege escalation and defense evasion technique that manipulates the SID-History attribute of user accounts to impersonate other users or gain elevated privileges. This technique is particularly dangerous because it allows attackers to maintain persistent access with elevated privileges by adding high-privilege SIDs to their account's SID-History, effectively granting them the permissions of those accounts. The detection community focuses on monitoring for tools that can manipulate Active Directory attributes (especially mimikatz), suspicious privilege escalations, and unauthorized modifications to user account SID-History attributes.

## What This Dataset Contains

This dataset captures a mimikatz-based SID-History injection attempt, though the tool appears to have failed. The key evidence includes:

**Process execution chain**: PowerShell → cmd.exe with mimikatz command line: `"cmd.exe" /c C:\AtomicRedTeam\atomics\..\ExternalPayloads\mimikatz\x64\mimikatz.exe "privilege::debug" "sid::patch" "sid::add /sid:S-1-5-21-1004336348-1177238915-682003330-1134 /sam:$env:username" "exit"`

**Privilege escalation preparation**: Security event 4703 shows token rights adjustment for the PowerShell process, enabling multiple sensitive privileges including `SeAssignPrimaryTokenPrivilege`, `SeSecurityPrivilege`, `SeBackupPrivilege`, and `SeRestorePrivilege` - all commonly required for low-level system manipulation.

**Process access telemetry**: Sysmon events 10 show PowerShell accessing both whoami.exe and cmd.exe processes with full access (`GrantedAccess: 0x1FFFFF`), indicating the parent process monitoring or interacting with its children.

**Tool execution failure**: The cmd.exe process exits with status code 0x1 (failure), and no mimikatz process creation is captured, suggesting Windows Defender or other security controls blocked the execution.

## What This Dataset Does Not Contain

**Mimikatz process creation**: No Sysmon ProcessCreate events show mimikatz.exe actually executing, likely because Windows Defender blocked it before process creation completed.

**LSASS access patterns**: No events show the characteristic LSASS process access that would occur if mimikatz successfully executed its privilege::debug and SID manipulation commands.

**Active Directory modifications**: No events capture the actual SID-History attribute modifications that would occur if the technique succeeded.

**Success telemetry**: The technique appears to have been blocked before completion, so we don't see the successful manipulation of user account attributes.

## Assessment

This dataset provides good telemetry for detecting SID-History injection attempts, particularly the command-line patterns and process execution chains. The Security event logs with full command-line auditing capture the complete mimikatz command with specific SID values and technique parameters. The privilege escalation events (4703) show the preparatory steps that often precede such attacks. However, since Windows Defender appears to have blocked the actual mimikatz execution, this dataset doesn't contain the full attack lifecycle or the more advanced detection opportunities that would come from successful tool execution and LSASS interaction.

## Detection Opportunities Present in This Data

1. **Mimikatz command-line detection** - Security event 4688 contains the explicit mimikatz.exe path and SID manipulation commands (`sid::patch`, `sid::add`) in the command line
2. **Suspicious privilege escalation** - Security event 4703 shows rapid enablement of multiple high-privilege tokens (SeAssignPrimaryTokenPrivilege, SeSecurityPrivilege, etc.) by a single process
3. **Tool path indicators** - Command line references `\ExternalPayloads\mimikatz\` directory structure commonly used in penetration testing frameworks
4. **SID injection parameters** - Command line contains specific SID format (`S-1-5-21-1004336348-1177238915-682003330-1134`) and SAM manipulation syntax
5. **Process execution anomalies** - PowerShell spawning cmd.exe with immediate external tool execution and subsequent failure exit code
6. **Parent-child process access** - Sysmon event 10 shows unusual parent process accessing child processes with full permissions, potentially indicating process monitoring or injection preparation
