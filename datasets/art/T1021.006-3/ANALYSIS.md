# T1021.006-3: Windows Remote Management — WinRM Access with Evil-WinRM

## Technique Context

T1021.006 (Windows Remote Management) is a lateral movement technique where attackers use Microsoft's WinRM service to establish remote command execution sessions on target systems. WinRM is Windows' implementation of the WS-Management protocol, providing a standardized way for administrators to remotely manage Windows systems. Attackers commonly leverage tools like Evil-WinRM, a PowerShell-based WinRM client, to establish interactive shells on compromised systems using valid credentials.

The detection community focuses on WinRM connection attempts, PowerShell execution patterns associated with WinRM clients, and network connections to TCP ports 5985/5986. Evil-WinRM specifically generates distinctive PowerShell command patterns and process execution chains that can be detected through endpoint telemetry.

## What This Dataset Contains

This dataset captures an attempted Evil-WinRM execution that appears to have failed quickly. The key evidence includes:

**PowerShell Script Block Logging (EID 4104):** Shows the Evil-WinRM command execution attempt: `evil-winrm -i Target -u Domain\Administrator -p P@ssw0rd1` in script block ID bc6353b9-6688-45cf-848d-ba23c6d1f9c0. The PowerShell channel is otherwise filled with boilerplate formatting script blocks typical of the test framework.

**Security Process Creation (EID 4688):** Documents the PowerShell process spawning with the full Evil-WinRM command line: `"powershell.exe" & {evil-winrm -i Target -u Domain\Administrator -p P@ssw0rd1}` executed by process ID 0xc68.

**Sysmon Process Creation (EID 1):** Captures the child PowerShell process (PID 3176) with the same Evil-WinRM command line, tagged with MITRE technique T1216 (System Script Proxy Execution).

**Process Access Events (EID 10):** Shows PowerShell processes accessing whoami.exe (PID 8076) and other PowerShell processes, indicating some command execution occurred before the tool failed.

**Named Pipe Creation (EID 17):** Documents PowerShell host pipes being created by multiple PowerShell processes, showing the tool's initialization attempts.

## What This Dataset Does Not Contain

This dataset lacks the telemetry that would indicate a successful WinRM connection. Missing elements include:

- **Network Connection Events:** No Sysmon EID 3 events showing outbound connections to WinRM ports (5985/5986) on the target system
- **WinRM Service Activity:** No Windows-RemoteManagement operational logs showing successful authentication or session establishment
- **Remote Shell Artifacts:** No evidence of interactive command execution or file transfer activities typical of successful Evil-WinRM sessions
- **Authentication Events:** No Security EID 4624/4625 events indicating remote logon attempts

The rapid process termination (all PowerShell processes exit within seconds) suggests the Evil-WinRM connection attempt failed, likely due to network connectivity issues or the target being unreachable.

## Assessment

This dataset provides limited but valuable telemetry for detecting Evil-WinRM usage attempts. The PowerShell script block logging captures the exact tool invocation with credentials in plaintext, and the process creation events document the execution chain. However, the failed connection attempt means this data represents detection opportunities for the initial stages of WinRM-based lateral movement rather than successful compromise.

The data quality is good for detecting Evil-WinRM tool usage but insufficient for understanding successful WinRM lateral movement patterns. The presence of both Security 4688 events with command-line logging and Sysmon process creation provides redundant coverage of the critical execution evidence.

## Detection Opportunities Present in This Data

1. **PowerShell Script Block Detection:** Alert on PowerShell script blocks containing "evil-winrm" command patterns with credential parameters (-u, -p flags)

2. **Command Line Analysis:** Monitor Security EID 4688 events for powershell.exe processes with "evil-winrm" in the command line, indicating tool usage attempts

3. **Process Chain Analysis:** Detect PowerShell parent-child relationships where the child process contains WinRM client tool command lines

4. **Credential Exposure Detection:** Flag PowerShell script blocks or command lines containing plaintext passwords in Evil-WinRM parameter format

5. **Tool-Specific Process Creation:** Alert on Sysmon EID 1 events where PowerShell processes are created with Evil-WinRM command syntax

6. **Rapid Process Termination Patterns:** Monitor for PowerShell processes executing WinRM client tools that terminate quickly, potentially indicating failed lateral movement attempts
