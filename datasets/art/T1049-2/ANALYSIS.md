# T1049-2: System Network Connections Discovery — System Network Connections Discovery with PowerShell

## Technique Context

T1049 (System Network Connections Discovery) involves adversaries enumerating network connections to understand the current network state and identify active connections that may be useful for lateral movement or persistence. This technique is commonly used during the discovery phase of an attack to map network topology, identify listening services, and discover potential pivot points. The PowerShell variant specifically uses `Get-NetTCPConnection` or similar cmdlets to enumerate TCP connections, which provides detailed information about local and remote endpoints, connection states, and associated processes.

Detection engineers focus on PowerShell-based network enumeration because it's a common method for both legitimate administration and malicious reconnaissance. The technique generates minimal network traffic but produces substantial host-based telemetry through PowerShell logging and process monitoring.

## What This Dataset Contains

This dataset captures a complete execution of PowerShell-based network connection discovery using the `Get-NetTCPConnection` cmdlet. The key evidence includes:

**Process Creation Chain**: Security event 4688 shows the parent PowerShell process spawning a child PowerShell process with command line `"powershell.exe" & {Get-NetTCPConnection}`, along with a `whoami.exe` execution for context gathering.

**PowerShell Script Block Logging**: Event 4104 captures the actual PowerShell execution with script blocks showing `& {Get-NetTCPConnection}` and `{Get-NetTCPConnection}`, along with the cmdlet invocation logged in event 4103 showing `CommandInvocation(Get-NetTCPConnection)` with parameters `ThrottleLimit=0` and `AsJob=False`.

**Sysmon Process Monitoring**: Sysmon event 1 captures both the `whoami.exe` execution (PID 16924) and the PowerShell child process (PID 15840) with full command lines and process relationships.

**Process Access Events**: Sysmon event 10 shows the parent PowerShell process accessing both the `whoami.exe` and child PowerShell processes with full access rights (0x1FFFFF), indicating process monitoring or injection capabilities.

**Runtime Evidence**: Multiple Sysmon event 7 entries document .NET Framework DLL loading in both PowerShell processes, including `System.Management.Automation.ni.dll` and various runtime components, confirming PowerShell execution context.

## What This Dataset Does Not Contain

The dataset does not contain the actual network connection enumeration results that `Get-NetTCPConnection` would have returned. There are no network-related Sysmon events (event ID 3 for network connections) because the cmdlet queries local system state rather than establishing new network connections. The dataset also lacks any file system artifacts that might result from output redirection, and there are no registry modifications associated with this discovery technique. Additionally, the PowerShell transcription logs are not present in this dataset, which would have captured the cmdlet output.

## Assessment

This dataset provides excellent coverage for detecting PowerShell-based network connection discovery. The combination of Security 4688 events with command-line logging, PowerShell script block logging (4104), and cmdlet invocation logging (4103) creates multiple detection opportunities. The Sysmon process creation events add valuable context about process relationships and execution flow. The process access events (Sysmon 10) may indicate additional suspicious behavior beyond simple discovery. However, the dataset would be stronger with PowerShell transcription logs to capture the actual enumerated network connections, which could help analysts understand the scope of discovery activity.

## Detection Opportunities Present in This Data

1. **PowerShell Network Discovery Cmdlets** - Monitor PowerShell event 4103 for `CommandInvocation(Get-NetTCPConnection)` or event 4104 script blocks containing `Get-NetTCPConnection`, `Get-NetUDPEndpoint`, or similar network enumeration cmdlets

2. **Suspicious PowerShell Command Line Patterns** - Detect Security 4688 events with PowerShell command lines containing network discovery patterns like `Get-NetTCPConnection`, `netstat` alternatives, or connection enumeration scripts

3. **PowerShell Process Spawning Chains** - Monitor for parent-child PowerShell process relationships where the child process executes network discovery commands, particularly when combined with other reconnaissance tools like `whoami.exe`

4. **Script Block Analysis** - Analyze PowerShell event 4104 script blocks for network enumeration patterns, especially when executed in non-interactive contexts or by system-level accounts

5. **Cross-Process Access During Discovery** - Correlate Sysmon event 10 process access events with PowerShell network discovery activities, particularly when PowerShell processes access other processes with full privileges during reconnaissance phases
