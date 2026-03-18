# T1070.001-2: Clear Windows Event Logs — Delete System Logs Using Clear-EventLog

## Technique Context

T1070.001 (Clear Windows Event Logs) is a fundamental defense evasion technique where adversaries attempt to remove evidence of their activities by clearing Windows event logs. This technique is commonly used after initial access or during post-exploitation phases to hinder forensic analysis and incident response efforts. The `Clear-EventLog` PowerShell cmdlet is a particularly common method for accomplishing this, as it can programmatically clear multiple event logs in a single operation.

Detection engineers focus on identifying the clearing of security-critical logs (especially Security and System), monitoring for privilege escalations that enable log clearing, and detecting the specific API calls and processes involved in log manipulation. The technique generates telemetry through multiple channels: the clearing action itself generates specific event IDs, process creation events capture the clearing commands, and PowerShell logging reveals the cmdlet usage.

## What This Dataset Contains

This dataset captures a comprehensive execution of PowerShell-based event log clearing using the `Clear-EventLog` cmdlet. The technique was executed with SYSTEM privileges and successfully cleared multiple Windows event logs.

**Process Chain and Commands:**
- Security EID 4688 shows PowerShell process creation with command line: `"powershell.exe" & {$logs = Get-EventLog -List | ForEach-Object {$_.Log} $logs | ForEach-Object {Clear-EventLog -LogName $_ } Get-EventLog -list}`
- Sysmon EID 1 captures the same PowerShell execution with full command visibility
- The technique systematically enumerates available logs and clears each one

**PowerShell Telemetry:**
- PowerShell EID 4103 (Module Logging) shows detailed cmdlet invocations for `Get-EventLog -List`, `ForEach-Object`, and critically multiple `Clear-EventLog` operations
- Specific logs cleared include: Application, HardwareEvents, Internet Explorer, Key Management Service, Security, System, and Windows PowerShell
- EID 4104 (Script Block Logging) captures the complete script block: `{$logs = Get-EventLog -List | ForEach-Object {$_.Log} $logs | ForEach-Object {Clear-EventLog -LogName $_ } Get-EventLog -list}`

**Log Clearing Evidence:**
- Security EID 1102 "The audit log was cleared" confirms successful Security log clearing
- System EID 104 events show "The System log file was cleared" and "The Windows PowerShell log file was cleared"
- Extensive Security EID 4703 events document privilege adjustments (SeBackupPrivilege, SeSecurityPrivilege) required for log clearing operations

**Process Behavior:**
- Sysmon shows PowerShell .NET runtime loading and Windows Defender integration
- Process access events (EID 10) show PowerShell accessing child processes
- Multiple privilege escalations captured in Security logs demonstrate the elevated permissions required

## What This Dataset Does Not Contain

The dataset does not contain evidence of alternative log clearing methods such as direct file manipulation of .evtx files, wevtutil usage, or WMI-based clearing techniques. There are no failed clearing attempts or access denied events, indicating the technique executed successfully without defensive interference. The dataset lacks evidence of log forwarding or centralized logging that might preserve cleared events elsewhere.

Windows Defender was active but did not block the technique, showing no blocking events or quarantine actions. The technique targeted traditional Windows event logs but did not attempt to clear more advanced logging sources like PowerShell Operational logs beyond the Windows PowerShell channel.

## Assessment

This dataset provides excellent detection engineering value for T1070.001. The multi-layered telemetry approach captures the technique through process creation monitoring (Security 4688), command-line logging, PowerShell module and script block logging, and the actual log clearing events themselves. The presence of both the clearing commands and the resulting clearing confirmations (EIDs 1102, 104) creates a complete attack narrative.

The privilege adjustment events (4703) are particularly valuable as they show the specific privileges required for log clearing operations, enabling detection of privilege escalation patterns associated with this technique. The detailed PowerShell logging reveals not just that logs were cleared, but exactly which logs and through what method.

The dataset would be stronger with examples of partial clearing failures or defensive responses, but as a successful execution example, it demonstrates all the key detection points for this technique.

## Detection Opportunities Present in This Data

1. **Event Log Clearing Detection** - Monitor Security EID 1102 and System EID 104 for log clearing events, especially when multiple logs are cleared in sequence
2. **Clear-EventLog PowerShell Cmdlet Usage** - Alert on PowerShell EID 4103 Module Logging showing Clear-EventLog cmdlet invocations with specific log names
3. **Bulk Log Enumeration and Clearing Script** - Detect PowerShell EID 4104 Script Block Logging containing `Get-EventLog -List` followed by `Clear-EventLog` patterns
4. **Privilege Escalation for Log Clearing** - Monitor Security EID 4703 for SeBackupPrivilege and SeSecurityPrivilege adjustments associated with PowerShell processes
5. **Process Command Line Analysis** - Hunt for Security EID 4688 with PowerShell command lines containing "Clear-EventLog" or log manipulation patterns
6. **Systematic Log Clearing Patterns** - Correlate multiple EID 104/1102 events occurring within short time windows as indicators of automated clearing
7. **PowerShell Process Chain Analysis** - Monitor Sysmon EID 1 for PowerShell parent-child relationships executing log clearing operations
8. **SYSTEM Context Log Clearing** - Alert on log clearing activities performed under SYSTEM or other high-privilege contexts as captured in process creation events
