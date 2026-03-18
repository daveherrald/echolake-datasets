# T1046-11: Network Service Discovery — Remote Desktop Services Discovery via PowerShell

## Technique Context

T1046 Network Service Discovery enables adversaries to gather information about services running on local or remote systems. This specific test (T1046-11) focuses on discovering Remote Desktop Services (RDS) components using PowerShell's `Get-Service` cmdlet. RDS discovery is particularly valuable to attackers as it reveals whether systems accept remote desktop connections, helping identify lateral movement opportunities or systems that may be accessible for credential harvesting. The detection community typically focuses on service enumeration commands, especially when targeting security-relevant services like RDS, Terminal Services, or authentication-related components.

## What This Dataset Contains

This dataset captures a PowerShell-based RDS discovery attempt executed as NT AUTHORITY\SYSTEM. The core technique appears in Security event 4688 showing the command line: `"powershell.exe" & {Get-Service -Name \"Remote Desktop Services\", \"Remote Desktop Configuration\"}`. 

PowerShell script block logging in event 4104 reveals the actual command executed: `Get-Service -Name "Remote Desktop Services", "Remote Desktop Configuration"` and the corresponding CommandInvocation event 4103 shows parameter binding with `name="Name"; value="Remote Desktop Services, Remote Desktop Configuration"`.

The process chain shows: initial powershell.exe (PID 25716) → child powershell.exe (PID 26616) with the service discovery command. Sysmon captures this child process creation in event 1 with rule name `technique_id=T1059.001,technique_name=PowerShell`, confirming PowerShell execution detection.

The dataset also includes typical PowerShell startup artifacts: .NET runtime loading (mscoree.dll, clr.dll), System.Management.Automation.ni.dll loading, and Windows Defender integration (MpOAV.dll, MpClient.dll loading). Named pipe creation events (Sysmon 17) show PowerShell IPC mechanisms.

## What This Dataset Does Not Contain

The dataset lacks the actual results of the service discovery command — we don't see whether the target services were found, their status, or any output handling. There are no network connections (Sysmon 3) since this is local service enumeration. Registry access events that might occur during service enumeration are not present, likely filtered by the Sysmon configuration. The PowerShell channel contains mostly test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy) rather than substantive script content beyond the core command.

## Assessment

This dataset provides excellent telemetry for detecting PowerShell-based service discovery targeting RDS components. The combination of Security 4688 command-line logging, PowerShell 4103/4104 script block logging, and Sysmon 1 process creation creates multiple detection layers. The technique executed successfully without Windows Defender interference, generating clean execution telemetry. However, the dataset would be stronger with evidence of command output or subsequent actions based on discovery results.

## Detection Opportunities Present in This Data

1. **PowerShell service enumeration commands** - Detect `Get-Service` cmdlet execution targeting RDS-related service names via PowerShell 4103 CommandInvocation events with parameter analysis
2. **Command-line service discovery patterns** - Monitor Security 4688 events for powershell.exe processes with command lines containing service enumeration targeting "Remote Desktop" services
3. **PowerShell script block analysis** - Alert on PowerShell 4104 script block events containing `Get-Service` with RDS-related service names as indicators of reconnaissance
4. **Process chain analysis** - Correlate parent-child PowerShell processes where child processes execute service enumeration commands via Sysmon 1 events
5. **RDS-specific service targeting** - Create focused detections for service enumeration specifically targeting "Remote Desktop Services" and "Remote Desktop Configuration" service names
