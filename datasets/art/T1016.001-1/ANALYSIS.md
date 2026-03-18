# T1016.001-1: Internet Connection Discovery — Check internet connection using ping Windows

## Technique Context

T1016.001 Internet Connection Discovery is a sub-technique under T1016 System Network Configuration Discovery, focusing specifically on adversary attempts to check for internet connectivity. This technique is fundamental to many attack chains as adversaries need to understand network reachability before attempting command and control communications, data exfiltration, or downloading additional payloads. The most common implementation uses ICMP ping to well-known external IP addresses like Google's DNS servers (8.8.8.8, 1.1.1.1) or major websites. Detection teams typically focus on identifying ping commands targeting external IPs, especially when executed by unusual processes or in suspicious contexts, though legitimate network troubleshooting can create false positives.

## What This Dataset Contains

This dataset captures a straightforward implementation of internet connectivity testing using ping. The technique executes through a clear process chain: `powershell.exe` → `cmd.exe` → `ping.exe`. The Security channel shows the complete process creation sequence with Security Event ID 4688 documenting:

- PowerShell spawning cmd.exe with command line `"cmd.exe" /c ping -n 4 8.8.8.8`
- cmd.exe spawning PING.EXE with command line `ping -n 4 8.8.8.8`
- whoami.exe execution (likely from test framework setup)

Sysmon provides complementary process creation events (EID 1) with additional context including process GUIDs, hashes, and parent-child relationships. The Sysmon data shows the ping command targeting Google's public DNS server 8.8.8.8 with 4 packets (`-n 4`). Process access events (Sysmon EID 10) capture PowerShell accessing both whoami.exe and cmd.exe processes with full access rights (0x1FFFFF).

## What This Dataset Does Not Contain

The dataset lacks network-level telemetry showing the actual ICMP packets leaving the system. There are no Sysmon Event ID 3 (Network Connection) events, likely because the sysmon-modular configuration may not capture ICMP traffic or ping network events. DNS resolution events (Sysmon EID 22) are absent, which would be expected if the ping command targeted a hostname instead of a direct IP address. The PowerShell channel contains only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) without the actual ping command invocation, indicating the technique was executed through direct process spawning rather than PowerShell cmdlets.

## Assessment

This dataset provides solid process-level telemetry for detecting internet connectivity checks via ping, particularly valuable for process-based detection rules. The Security 4688 events with command-line logging offer reliable detection opportunities, while Sysmon EID 1 provides additional context like process hashes and integrity levels. However, the absence of network telemetry limits visibility into whether the ping actually succeeded or what responses were received. The technique represents a basic but realistic implementation that many adversaries would use, making the telemetry patterns broadly applicable.

## Detection Opportunities Present in This Data

1. **Process creation of ping.exe targeting external IP addresses** - Security EID 4688 and Sysmon EID 1 showing ping.exe with command lines containing external IPs like 8.8.8.8

2. **Command shell executing network discovery commands** - cmd.exe process creation with command lines containing "ping" followed by external IP addresses

3. **PowerShell spawning system utilities for network discovery** - Process chain analysis showing powershell.exe as parent of cmd.exe executing ping commands

4. **Suspicious process access patterns** - Sysmon EID 10 showing PowerShell accessing cmd.exe and other child processes with full access rights during network discovery activities

5. **Multiple network utility executions in sequence** - Temporal correlation of whoami.exe followed by ping.exe execution, indicating potential reconnaissance activity
