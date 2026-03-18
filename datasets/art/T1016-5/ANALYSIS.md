# T1016-5: System Network Configuration Discovery — List Open Egress Ports

## Technique Context

T1016 System Network Configuration Discovery is a reconnaissance technique where adversaries gather information about network configurations, interfaces, and connectivity to understand the target environment. The specific sub-technique demonstrated here involves port scanning — attempting TCP connections to a list of common ports on an external target to identify which services may be accessible. This technique helps attackers understand network egress capabilities, potential command and control channels, and services running on remote systems.

Detection engineers typically focus on identifying automated port scanning behaviors, DNS resolution patterns for suspicious domains, and network connection attempts to non-standard or suspicious destinations. The technique often generates distinctive patterns of rapid successive connection attempts across multiple ports.

## What This Dataset Contains

This dataset captures a PowerShell-based port scanning implementation that reads port numbers from "C:\AtomicRedTeam\atomics\T1016\src\top-128.txt" and attempts TCP connections to "allports.exposed" across 128 common ports. The Security channel provides the primary detection evidence with Security 4688 showing the PowerShell execution with the full command line: `"powershell.exe" & {$ports = Get-content \"C:\AtomicRedTeam\atomics\T1016\src\top-128.txt\"... $test = new-object system.Net.Sockets.TcpClient... $wait = $test.beginConnect(\"allports.exposed\", $port, $null, $null)...}`

Sysmon captures complementary evidence including Sysmon 1 (Process Create) events for the PowerShell processes and whoami.exe execution, Sysmon 22 (DNS Query) events showing 128 DNS resolution attempts for "allports.exposed" with QueryStatus 9501 (DNS name does not exist), and Sysmon 11 (File Create) events for the output file "C:\Windows\System32\config\systemprofile\Desktop\open-ports.txt".

The PowerShell channel contains the full script block via EID 4104, showing the port scanning logic including TcpClient instantiation, connection attempts with 250ms timeout, and result logging to a desktop file.

## What This Dataset Does Not Contain

This dataset lacks network connection telemetry because the target domain "allports.exposed" doesn't resolve (QueryStatus 9501 in all DNS queries), preventing actual TCP connection attempts from being established. No Sysmon 3 (Network Connect) events are present since the connections failed at DNS resolution. The technique doesn't demonstrate successful port enumeration results since all connection attempts would have failed, and there are no registry modifications or additional file system artifacts beyond the output file creation.

## Assessment

This dataset provides excellent detection opportunities for port scanning behaviors through the combination of command line analysis, DNS query patterns, and PowerShell script block logging. The Security 4688 events with full command lines are particularly valuable for detecting the TcpClient instantiation and connection attempt patterns. The volume of DNS queries (128 rapid attempts to the same domain) creates a distinctive pattern ideal for detection rules. However, the dataset would be strengthened by including successful connection attempts to demonstrate the full network-level artifacts that would be generated in a real scenario.

## Detection Opportunities Present in This Data

1. **PowerShell Port Scanning Command Lines** - Security 4688 events containing "system.Net.Sockets.TcpClient" and "beginConnect" strings indicating programmatic network connection attempts

2. **Rapid DNS Query Patterns** - Multiple Sysmon 22 events showing repeated DNS queries to the same domain within a short timeframe (128 queries to "allports.exposed" in under one second)

3. **PowerShell Script Block with Network Objects** - PowerShell 4104 events containing "TcpClient", "beginConnect", and port iteration loops indicating automated network scanning

4. **Port Scanning Output File Creation** - Sysmon 11 events showing creation of files with names like "open-ports.txt" in user profile directories

5. **PowerShell Network Library Loading** - Process creation events spawning PowerShell with command lines referencing .NET Socket classes for network operations

6. **DNS Query Failure Patterns** - Consistent DNS query failures (QueryStatus 9501) across multiple rapid queries, potentially indicating scanning of non-existent infrastructure

7. **Process Chain Analysis** - Parent-child relationships showing PowerShell spawning from another PowerShell process with network-related command line arguments
