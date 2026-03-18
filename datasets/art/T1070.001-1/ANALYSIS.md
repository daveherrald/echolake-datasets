# T1070.001-1: Clear Windows Event Logs — Clear Logs

## Technique Context

T1070.001 (Clear Windows Event Logs) is a defense evasion technique where adversaries clear Windows event logs to remove evidence of their activities. This is a common post-exploitation activity used to hide traces of lateral movement, privilege escalation, data exfiltration, or other malicious activities. Attackers typically use built-in Windows utilities like `wevtutil.exe` or PowerShell cmdlets like `Clear-EventLog` to clear specific event logs or all logs on a system.

The detection community focuses on monitoring for the use of log-clearing utilities, unusual process command lines targeting event logs, and the actual event log clearing events (System Event ID 104). This technique is particularly important because it represents an attempt to evade detection and indicates that an adversary is actively trying to cover their tracks.

## What This Dataset Contains

This dataset captures the complete execution chain of clearing the System event log using `wevtutil.exe`. The attack flow shows:

**Process Chain**: PowerShell spawns cmd.exe which then executes wevtutil to clear logs:
- Security 4688: `"cmd.exe" /c wevtutil cl System` (PID 24556, parent PowerShell PID 19728)
- Security 4688: `wevtutil  cl System` (PID 39196, parent cmd.exe PID 24556)
- Sysmon 1: Same process creations with additional context and hashes

**Log Clearing Evidence**: The actual log clearing event is captured:
- System 104: "The System log file was cleared" - this is the definitive evidence that log clearing occurred

**Privilege Activity**: Multiple Security 4703 events show wevtutil enabling and then disabling the necessary privileges:
- SeSecurityPrivilege and SeBackupPrivilege enabled for PID 39196 (wevtutil.exe)
- Both privileges subsequently disabled after the operation

**PowerShell Telemetry**: The PowerShell channel contains only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) with no actual technique-specific script content.

**Sysmon Process Details**: Sysmon captures the wevtutil execution with full command line, hashes, and parent process information, including the RuleName classification as "technique_id=T1070.001,technique_name=Clear Windows Event Logs".

## What This Dataset Does Not Contain

The dataset lacks the initial PowerShell script content that triggered the log clearing - the PowerShell events show only framework setup code rather than the actual Atomic Red Team script. While we see the process creation events, we don't capture the specific PowerShell cmdlet or method used to invoke the system command.

The dataset also doesn't show clearing of other event logs (Security, Application, or custom logs) - only the System log was targeted in this test. Additionally, there are no network-based log clearing activities or remote event log manipulation attempts.

## Assessment

This dataset provides excellent telemetry for detecting T1070.001 through multiple complementary data sources. The combination of System Event ID 104 (definitive proof of log clearing), Security 4688 events with command lines, Sysmon ProcessCreate events with detailed metadata, and privilege adjustment events (4703) creates a robust detection foundation.

The data quality is strong with complete process chains, accurate timestamps, and proper parent-child relationships. The inclusion of both the execution telemetry and the actual log clearing event (System 104) makes this particularly valuable for building multi-layered detection rules.

## Detection Opportunities Present in This Data

1. **System Event ID 104 Monitoring**: Alert on any occurrence of "The System log file was cleared" events, as legitimate log clearing is typically rare and scheduled

2. **Command Line Detection**: Monitor Security 4688 and Sysmon 1 events for command lines containing "wevtutil" with "cl" (clear) parameter combinations

3. **Process Chain Analysis**: Detect suspicious parent-child relationships where PowerShell or cmd.exe spawn wevtutil.exe with log clearing arguments

4. **Privilege Escalation Correlation**: Alert on Security 4703 events showing SeSecurityPrivilege and SeBackupPrivilege being enabled by wevtutil.exe

5. **PowerShell to System Tool Chaining**: Monitor for PowerShell processes spawning command-line utilities known for log manipulation

6. **Behavioral Clustering**: Correlate log clearing activities with other defense evasion techniques occurring in similar timeframes

7. **Anomaly Detection**: Flag wevtutil.exe execution during unusual hours or by unexpected user accounts

8. **Hash-based Detection**: Use the captured wevtutil.exe hashes (SHA256: 97AFBE889BB9879A43E313097EBAC19522412F254049B07B70CD7C15500C3FC6) to verify process authenticity
