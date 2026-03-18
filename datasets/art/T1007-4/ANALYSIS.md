# T1007-4: System Service Discovery — Get-Service Execution

## Technique Context

T1007 System Service Discovery is a reconnaissance technique where adversaries enumerate services on compromised systems to understand the security posture, identify potential targets for privilege escalation, or locate security tools that might interfere with their operations. The PowerShell `Get-Service` cmdlet is a common method for this discovery, as it provides comprehensive service information including status, startup type, and dependencies. Detection engineers focus on identifying unusual service enumeration patterns, especially when combined with other reconnaissance activities or executed from suspicious contexts. This technique is often seen early in attack chains during initial system assessment phases.

## What This Dataset Contains

This dataset captures a straightforward execution of `Get-Service` through multiple PowerShell processes. The primary evidence includes:

- **Security 4688 events** showing the full process chain: initial PowerShell → cmd.exe → second PowerShell with command line `powershell.exe Get-Service`
- **Sysmon EID 1 events** capturing three key process creations: whoami.exe execution (Process ID 6936), cmd.exe with command `"cmd.exe" /c powershell.exe Get-Service` (Process ID 7072), and the final PowerShell process with `powershell.exe Get-Service` (Process ID 6324)
- **PowerShell operational logs** containing the actual Get-Service cmdlet execution in EID 4103 and 4104 events, specifically showing `CommandInvocation(Get-Service): "Get-Service"` and the script block `Get-Service`
- **Process access events** (Sysmon EID 10) showing the PowerShell process accessing both whoami.exe and cmd.exe with full access rights (0x1FFFFF)
- **Image load events** (Sysmon EID 7) documenting .NET runtime components and Windows Defender integration during PowerShell execution

The execution sequence shows NT AUTHORITY\SYSTEM running multiple PowerShell processes with complete privilege escalation logging via Security EID 4703, indicating extensive system privileges were enabled.

## What This Dataset Does Not Contain

The dataset lacks several elements that would be present in a more comprehensive service discovery operation:

- **No Service Control Manager interactions** - Missing events that would show actual service database queries or WMI calls that Get-Service typically generates
- **No network artifacts** - Service enumeration on remote systems would generate network connections not present here
- **Limited output capture** - The actual service enumeration results aren't logged in these event channels
- **No persistence indicators** - This is a one-time execution without evidence of scripted or automated service discovery
- **Missing WMI telemetry** - Get-Service often uses WMI providers, but no WMI events are captured in this dataset

The sysmon-modular configuration's include-mode filtering explains why many expected child processes aren't captured in Sysmon ProcessCreate events.

## Assessment

This dataset provides solid foundational telemetry for detecting PowerShell-based service discovery but has significant gaps for comprehensive detection engineering. The Security audit logs offer complete process tracking with command lines, making them the most reliable detection source. The PowerShell operational logs clearly show the Get-Service cmdlet execution, which is valuable for PowerShell-focused detections. However, the absence of Service Control Manager events and WMI telemetry limits understanding of the actual system impact and information gathered. The dataset effectively demonstrates the process execution chain but lacks the service enumeration artifacts that would indicate what information was actually obtained by the adversary.

## Detection Opportunities Present in This Data

1. **PowerShell Service Discovery Cmdlet** - Monitor PowerShell EID 4103/4104 for Get-Service cmdlet invocations, especially when executed with system-level privileges or in non-interactive contexts

2. **Process Chain Analysis** - Detect the specific execution pattern of PowerShell → cmd.exe → PowerShell with Get-Service parameter using Security 4688 events to identify indirect PowerShell execution

3. **Privileged Service Enumeration** - Alert on Get-Service execution under NT AUTHORITY\SYSTEM context, particularly when combined with other reconnaissance commands like whoami

4. **Command Line Pattern Matching** - Create signatures for the command pattern `"cmd.exe" /c powershell.exe Get-Service` in Security 4688 events to catch this specific service discovery method

5. **PowerShell Process Access Anomalies** - Monitor Sysmon EID 10 events where PowerShell processes access system utilities with full rights (0x1FFFFF) as potential indicators of reconnaissance activity

6. **Cross-Process PowerShell Execution** - Detect when PowerShell spawns additional PowerShell processes for single commands, which may indicate evasion attempts or automated tooling
