# T1016.001-5: Internet Connection Discovery — Check internet connection using Test-NetConnection in PowerShell (TCP-SMB)

## Technique Context

T1016.001 Internet Connection Discovery is a reconnaissance technique where adversaries attempt to check for internet connectivity to understand network egress capabilities and determine whether a compromised host can communicate with external command and control infrastructure. The Test-NetConnection PowerShell cmdlet is a legitimate administrative tool commonly used for network troubleshooting that adversaries often leverage for this purpose. This specific test variant attempts to connect to Google's public DNS server (8.8.8.8) on TCP port 445 (SMB), which would normally fail since Google doesn't run SMB services, but provides insight into network connectivity and firewall rules. Detection engineers focus on identifying unusual network connectivity tests, especially to external IP addresses on unexpected ports, and monitoring for reconnaissance patterns that precede other malicious activities.

## What This Dataset Contains

This dataset captures a comprehensive execution of PowerShell's Test-NetConnection cmdlet attempting to connect to 8.8.8.8 on TCP port 445. The Security channel shows the complete process lifecycle with Security 4688 events documenting the PowerShell process creation with command line `"powershell.exe" & {Test-NetConnection -CommonTCPPort SMB -ComputerName 8.8.8.8}`, followed by whoami.exe execution for user discovery. The PowerShell channel contains extensive 4103 and 4104 events showing the cmdlet's internal operations including DNS resolution attempts, TCP connection testing, ICMP ping tests, and network routing analysis. Specific PowerShell events capture `TestTCP` function calls with parameters `TargetIPAddress: 8.8.8.8` and `TargetPort: 445`, along with `Resolve-DnsName` operations and `Find-NetRoute` calls. The Sysmon channel provides process creation events for both powershell.exe processes (PIDs 2592 and 7272) with Sysmon 1 events, plus extensive .NET runtime library loading through Sysmon 7 events, and process access events showing PowerShell accessing child processes.

## What This Dataset Does Not Contain

The dataset lacks network connection telemetry that would show the actual TCP connection attempt to 8.8.8.8:445. While Sysmon is configured with network connection monitoring enabled, no Sysmon 3 (NetworkConnect) events appear in the data, likely because the connection attempt failed quickly due to Google not accepting SMB connections. The PowerShell 4103 events explicitly show the connection failure with the message "TCP connect to (8.8.8.8 : 445) failed" and debug information indicating a timeout. Additionally, DNS query telemetry (Sysmon 22) events are absent, though PowerShell logs show DNS resolution attempts through the Resolve-DnsName cmdlet. The test appears to have completed successfully from a PowerShell perspective despite the network connection failure, so there are no error conditions or blocked execution events from Windows Defender.

## Assessment

This dataset provides excellent telemetry for detecting Internet Connection Discovery attempts using Test-NetConnection. The PowerShell logging is particularly comprehensive, capturing the full cmdlet execution chain with specific parameters that clearly indicate external connectivity testing. The command-line logging in Security 4688 events provides immediate detection value with the explicit Test-NetConnection syntax. The combination of process creation, PowerShell module logging, and detailed cmdlet invocation data creates multiple detection opportunities. However, the lack of actual network connection events limits visibility into successful connections, though the PowerShell logs compensate by documenting the connection attempt results. This data would strongly support detection rules focused on reconnaissance activities and network discovery patterns.

## Detection Opportunities Present in This Data

1. **PowerShell Test-NetConnection cmdlet execution** - Monitor PowerShell 4103 events for Test-NetConnection CommandInvocation with external IP addresses and suspicious port combinations
2. **Process creation with network testing command lines** - Alert on Security 4688 events with command lines containing "Test-NetConnection" and external IP addresses like "8.8.8.8"
3. **DNS resolution of external hosts for connectivity testing** - Monitor PowerShell 4103 events showing Resolve-DnsName operations against public DNS servers or external IPs
4. **Network routing discovery attempts** - Detect PowerShell 4103 events invoking Find-NetRoute cmdlets with external IP addresses as targets
5. **TCP connection testing to non-standard ports** - Monitor PowerShell events showing TestTCP function calls with external IPs and ports like 445 to non-SMB hosts
6. **PowerShell script block creation for network reconnaissance** - Alert on PowerShell 4104 events containing Test-NetConnection cmdlet text in script blocks
7. **Process chain analysis for discovery techniques** - Correlate whoami.exe execution (T1033) following network connectivity tests as part of broader reconnaissance patterns
