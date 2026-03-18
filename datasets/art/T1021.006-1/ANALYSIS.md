# T1021.006-1: Windows Remote Management — Enable Windows Remote Management

## Technique Context

Windows Remote Management (WinRM) is Microsoft's implementation of the WS-Management protocol, providing a standardized way for systems to access and exchange management information across networks. T1021.006 focuses on attackers' use of WinRM for lateral movement within Windows environments, often leveraging legitimate credentials or authentication mechanisms to execute commands remotely.

The detection community prioritizes monitoring WinRM activity because it represents a powerful legitimate administrative tool that attackers frequently abuse. Key focus areas include WinRM service startup, listener configuration changes, unusual authentication patterns, and remote PowerShell sessions. Enable-PSRemoting is particularly significant as it configures the system to accept remote PowerShell connections, effectively expanding the attack surface for lateral movement.

## What This Dataset Contains

This dataset captures the complete execution of PowerShell's `Enable-PSRemoting -Force` command, providing rich telemetry across multiple log sources:

**Process Creation Events (Security 4688):**
- Initial PowerShell process: `"powershell.exe" & {Enable-PSRemoting -Force}` (PID 7640)
- WinRM service startup: `C:\Windows\System32\svchost.exe -k NetworkService -p -s WinRM` (PID 7864)

**PowerShell Script Block Logging (4104/4103):**
- Full Enable-PSRemoting function definition with internal logic for service configuration
- CIM/WMI cmdlet invocations for service management: `Get-Service winrm`, `Get-CimInstance`, `Set-WSManQuickConfig`
- Session configuration enumeration and security descriptor modifications

**WinRM Service Events (System channel):**
- Service status transitions: "The WinRM service is not listening" (EID 10149) followed by "The WinRM service is listening" (EID 10148)
- HTTP listener configuration: URL additions for ports 47001 and 5985 (EID 113)
- Security warning about basic authentication over HTTP (EID 10121)

**Sysmon Network Activity:**
- Multiple TCP connections from PowerShell (PID 7640) to localhost:47001 (WS-Management port)
- IPv6 loopback connections indicating local WinRM configuration testing

**Registry Modifications (Sysmon EID 13):**
- Windows Firewall rule creation for WinRM: `WINRM-HTTP-In-TCP-NoScope` rule activation
- Registry epoch updates tracking firewall policy changes

## What This Dataset Does Not Contain

The dataset lacks several important elements for comprehensive WinRM detection:

**Missing Remote Connection Telemetry:** Since this is local configuration only, there are no actual incoming remote connections or authentication events that would typically accompany lateral movement attempts.

**Limited Network Indicators:** The network connections shown are localhost-to-localhost configuration testing, not the external network activity that would indicate actual remote access attempts.

**WinRM-Specific Authentication Logs:** No Security event IDs 4624/4625 showing remote logons via WinRM, nor the specialized WinRM authentication events that would accompany remote sessions.

**PowerShell Remoting Session Data:** No evidence of actual PSSession establishment, remote command execution, or the distinctive PowerShell remoting artifacts that would indicate active use.

## Assessment

This dataset provides excellent coverage of the WinRM enablement process itself, making it valuable for detecting initial system compromise preparation rather than active lateral movement. The combination of process telemetry, PowerShell logging, system events, and network activity creates a comprehensive signature for Enable-PSRemoting execution.

The PowerShell script block logging is particularly valuable, capturing the full internal logic of the Enable-PSRemoting function including service state checks, firewall configuration, and security descriptor modifications. The System channel events provide authoritative confirmation of WinRM service state changes.

However, the dataset's utility is limited to detecting the preparation phase of T1021.006 rather than active exploitation. For complete lateral movement detection, additional telemetry showing incoming connections, authentication events, and remote command execution would be necessary.

## Detection Opportunities Present in This Data

1. **Enable-PSRemoting Command Execution** - PowerShell 4104 events containing "Enable-PSRemoting" function definition or 4103 CommandInvocation events for the cmdlet

2. **WinRM Service Configuration Changes** - System events 10148/10149 indicating WinRM service listener state transitions, particularly rapid off-to-on transitions

3. **WinRM Port Listener Creation** - System EID 113 events showing HTTP URL group additions for ports 5985 or 47001 within short time windows

4. **PowerShell-to-WinRM Network Connections** - Sysmon EID 3 showing PowerShell processes connecting to localhost:47001, indicating WinRM configuration testing

5. **WinRM Firewall Rule Activation** - Registry modifications (Sysmon EID 13) creating or enabling WINRM-HTTP firewall rules, especially rapid FALSE-to-TRUE state changes

6. **WS-Management Configuration Commands** - PowerShell 4103 events for Set-WSManQuickConfig, Get-PSSessionConfiguration, or other WS-Management cmdlets executed in sequence

7. **Combined WinRM Enablement Pattern** - Temporal correlation of PowerShell execution, system service changes, firewall modifications, and network testing within a narrow time window (typically under 30 seconds)
