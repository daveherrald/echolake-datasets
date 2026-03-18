# T1039-1: Data from Network Shared Drive — Copy a sensitive File over Administrative share with copy

## Technique Context

T1039 (Data from Network Shared Drive) involves adversaries collecting data from network-accessible file shares and removable media. This technique is commonly used during the Collection phase to gather sensitive information from shared drives, administrative shares (like C$, ADMIN$), or mapped network drives. Attackers often leverage legitimate tools like `copy`, `xcopy`, `robocopy`, or PowerShell cmdlets to transfer files from remote systems they have gained access to.

The detection community focuses on monitoring file access patterns to network shares, especially administrative shares, unusual copy operations involving sensitive file types, and processes accessing remote paths with UNC notation. Key indicators include command-line arguments containing UNC paths, file creation events in temporary directories from network sources, and authentication events to administrative shares.

## What This Dataset Contains

This dataset captures a straightforward file copy operation from an administrative share using the built-in Windows `copy` command. The core technique evidence appears in Security event 4688 showing the command execution:

`"cmd.exe" /c copy \\127.0.0.1\C$\Windows\temp\Easter_Bunny.password %TEMP%\Easter_egg.password`

The process chain shows PowerShell (PID 8004) spawning cmd.exe (PID 7680) to execute the copy command. The command fails with exit status 0x1, indicating the source file likely doesn't exist or access was denied. Sysmon captures the cmd.exe process creation (EID 1) with the full command line showing the UNC path `\\127.0.0.1\C$\` accessing the local administrative C$ share.

Additional context includes multiple PowerShell processes starting and stopping, whoami.exe execution for user discovery (T1033), and various .NET runtime DLL loads in PowerShell processes. The PowerShell logs contain only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) with no technique-specific script blocks.

## What This Dataset Does Not Contain

The dataset lacks several important elements for complete T1039 analysis. There are no network authentication events (Security 4624/4625) showing connection to the administrative share, no object access auditing events (Security 4656/4658) for file access attempts, and no successful file creation events showing the copied file in the destination. The copy command's exit status 0x1 suggests the operation failed, so there's no evidence of successful data exfiltration.

Missing are Sysmon network connection events (EID 3) that would show SMB connections to the share, file creation events (EID 11) for the destination file, and any file deletion events if cleanup occurred. The technique appears to have been blocked or failed, limiting the telemetry to process execution rather than successful data collection.

## Assessment

This dataset provides good process execution telemetry for detecting T1039 attempts but lacks the network and file access events that would indicate successful technique completion. The Security 4688 events with command-line logging are excellent for catching UNC path usage in copy operations, while Sysmon EID 1 provides additional process creation context with parent-child relationships.

The data quality is good for building detections around command-line patterns and process behavior, but the failed execution limits its utility for understanding post-exploitation file handling or network share access patterns. The multiple PowerShell process creations suggest this was part of a larger automated test execution rather than a standalone technique demonstration.

## Detection Opportunities Present in This Data

1. **UNC Path Copy Operations** - Security 4688 command lines containing `copy` commands with UNC paths (\\servername\share$) indicate potential administrative share access attempts

2. **Administrative Share Access Patterns** - Command lines accessing C$, ADMIN$, or other administrative shares via UNC notation (\\127.0.0.1\C$, \\hostname\C$)

3. **PowerShell-to-CMD Process Chain** - PowerShell spawning cmd.exe for file operations may indicate scripted data collection activities

4. **Sensitive File Extensions in Copy Commands** - Command lines copying files with extensions like .password, .key, .crt, or other credential-related file types

5. **Localhost Administrative Share Access** - Specific pattern of accessing local administrative shares via loopback addresses (\\127.0.0.1\C$) which may indicate lateral movement testing or privilege escalation verification

6. **Failed Copy Operations** - Process exit codes (0x1) combined with copy commands can help identify failed exfiltration attempts that may indicate defensive measures or missing source files

7. **TEMP Directory as Copy Destination** - File operations copying from network shares to %TEMP% directories often indicate staging for further exfiltration or processing
