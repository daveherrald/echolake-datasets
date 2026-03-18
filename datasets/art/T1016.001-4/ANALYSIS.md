# T1016.001-4: Internet Connection Discovery — Check internet connection using Test-NetConnection in PowerShell (TCP-HTTP)

## Technique Context

T1016.001 Internet Connection Discovery is a Discovery technique where adversaries determine if the compromised system has internet connectivity. This reconnaissance helps attackers understand network topology, plan data exfiltration routes, and decide on command and control strategies. The `Test-NetConnection` PowerShell cmdlet is particularly valuable for this purpose as it's a legitimate Windows networking tool that performs DNS resolution, TCP port connectivity tests, and can check common service ports like HTTP (80) and HTTPS (443).

The detection community focuses heavily on monitoring PowerShell execution, especially cmdlets that perform network operations. `Test-NetConnection` usage targeting external domains is a common indicator of discovery activity, though legitimate administrative use makes this challenging to detect without context. Key detection points include PowerShell script block logging, command-line monitoring, DNS queries to external domains, and network connection attempts.

## What This Dataset Contains

This dataset captures a comprehensive execution of `Test-NetConnection -CommonTCPPort HTTP -ComputerName www.google.com` with excellent telemetry coverage:

**PowerShell Execution Chain**: Security event 4688 shows the process creation: `"powershell.exe" & {Test-NetConnection -CommonTCPPort HTTP -ComputerName www.google.com}`. The command spawns from an initial PowerShell process (PID 8112) that creates a child PowerShell process (PID 8116) to execute the Test-NetConnection command.

**PowerShell Script Block Logging**: Event 4104 captures the actual command execution: `{Test-NetConnection -CommonTCPPort HTTP -ComputerName www.google.com}`. PowerShell module invocation logging (4103) shows detailed cmdlet execution including `Test-NetConnection` with parameters `ComputerName=www.google.com` and `CommonTCPPort=HTTP`, plus internal function calls like `ResolveTargetName`, `TestTCP`, and DNS resolution operations.

**DNS Resolution**: Multiple Sysmon event 22 entries capture DNS queries for "www.google.com" with successful resolution to Google's IP addresses (142.251.152.119, etc.) and IPv6 addresses. One query shows status 1460 (timeout) for LLMNR/NetBIOS resolution, which is expected behavior.

**Network Discovery Details**: PowerShell logging reveals the internal mechanics - DNS resolution using `Resolve-DnsName`, TCP connectivity testing to port 80 on resolved IP 142.251.152.119, network route discovery with `Find-NetRoute`, and network adapter enumeration with `Get-NetAdapter`.

**Process Telemetry**: Sysmon event 1 captures the PowerShell process creation with the full command line. Multiple image load events (Sysmon 7) show .NET runtime loading, PowerShell automation libraries, and Windows Defender components engaging with the process.

## What This Dataset Does Not Contain

The dataset lacks actual network connection telemetry. While we see DNS resolution and the Test-NetConnection execution, there are no Sysmon event 3 (NetworkConnect) entries showing the actual TCP connection attempt to port 80 on Google's servers. This could indicate the sysmon-modular configuration filters these connections, or the connection attempt failed/wasn't completed during the capture window.

Windows Firewall or network security policy events are absent, though the PowerShell logging shows `Find-NetIPsecRule` and network isolation queries were performed. The technique completed successfully based on PowerShell execution, but we don't see the final connection result or any network traffic analysis.

Process access events (Sysmon 10) show PowerShell accessing whoami.exe and itself, but this appears to be administrative context checking rather than core technique functionality.

## Assessment

This dataset provides excellent coverage for detecting PowerShell-based internet connectivity testing. The combination of command-line logging (Security 4688), PowerShell script block logging (4104), module invocation logging (4103), and DNS query monitoring (Sysmon 22) creates multiple detection opportunities at different stages of the technique execution.

The PowerShell telemetry is particularly rich, showing not just the high-level command but the internal function calls and parameters. This level of detail supports both signature-based detection and behavioral analysis. The DNS resolution data provides network-layer detection opportunities that are harder to evade.

Missing network connection events limit visibility into the actual success/failure of the connectivity test, but the abundant PowerShell logging more than compensates for building effective detections around this technique variant.

## Detection Opportunities Present in This Data

1. **PowerShell Test-NetConnection Usage**: Monitor PowerShell script block logging (4104) for `Test-NetConnection` cmdlet execution, especially with external domain targets and common port parameters like `-CommonTCPPort HTTP`.

2. **Command Line Detection**: Alert on Security event 4688 process creation with command lines containing `Test-NetConnection` combined with external domain names and port specifications.

3. **PowerShell Module Invocation Patterns**: Use event 4103 to detect the specific function call pattern: `Test-NetConnection` followed by `ResolveTargetName`, `TestTCP`, and `Resolve-DnsName` operations against external domains.

4. **DNS Query Analysis**: Monitor Sysmon event 22 for DNS resolution of well-known external domains (google.com, microsoft.com, etc.) from PowerShell processes, particularly when correlated with Test-NetConnection activity.

5. **PowerShell Network Function Sequences**: Detect the characteristic sequence of PowerShell network functions: DNS resolution, network route discovery (`Find-NetRoute`), adapter enumeration (`Get-NetAdapter`), and network security analysis (`Find-NetIPsecRule`).

6. **Cross-Process PowerShell Execution**: Monitor for PowerShell processes spawning child PowerShell processes with network testing commands, indicating potential scripted or automated discovery activity.

7. **Administrative Context Network Testing**: Flag Test-NetConnection usage from SYSTEM context or elevated PowerShell sessions, which may indicate compromise rather than legitimate troubleshooting.
