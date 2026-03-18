# T1105-13: Ingress Tool Transfer — Download a File with Windows Defender MpCmdRun.exe

## Technique Context

T1105 Ingress Tool Transfer represents adversaries' attempts to transfer tools and files from external systems into a compromised environment. This technique is fundamental to multi-stage attacks where attackers need to bring in additional payloads, tools, or data after initial access. The detection community focuses heavily on monitoring file downloads, especially those using Living-Off-The-Land Binaries (LOLBins) that abuse legitimate system tools for malicious purposes.

This specific test (T1105-13) demonstrates a particularly concerning abuse vector: using Windows Defender's command-line utility `MpCmdRun.exe` with its `-DownloadFile` parameter to fetch external files. This technique is especially stealthy because it uses Microsoft's own security product to perform the download, potentially bypassing security controls that might otherwise flag suspicious download activity from unknown processes.

## What This Dataset Contains

The dataset captures an attempt to use MpCmdRun.exe for file download that was blocked by Windows Defender itself. The key evidence appears in Security event 4688, showing the command execution:

`"cmd.exe" /c cd "%ProgramData%\Microsoft\Windows Defender\platform\4.18*" & MpCmdRun.exe -DownloadFile -url https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/LICENSE.txt -path %temp%\Atomic-license.txt`

The command failed with exit code `0xC0000022` (STATUS_ACCESS_DENIED), indicating Windows Defender blocked the operation. The PowerShell test framework executed `whoami.exe` (captured in Sysmon EID 1) before attempting the download. Sysmon captured extensive .NET and PowerShell module loading (EIDs 7), named pipe creation (EID 17), process injection events (EIDs 8, 10), and file creation events (EID 11) related to PowerShell startup profiling.

The PowerShell channel contains only boilerplate test framework activity (`Set-StrictMode`, `Set-ExecutionPolicy Bypass`) without the actual technique execution content.

## What This Dataset Does Not Contain

This dataset lacks the successful execution telemetry that would occur if the download completed. There are no network connection events (Sysmon EID 3) showing the HTTP request to GitHub, no file creation events for the target file `%temp%\Atomic-license.txt`, and no MpCmdRun.exe process creation events in Sysmon (the sysmon-modular config's include-mode filtering doesn't capture MpCmdRun.exe as a suspicious process).

Critically missing is any evidence of the actual MpCmdRun.exe execution - we only see the cmd.exe wrapper that was blocked. Windows Defender's real-time protection prevented the technique from completing, so we observe the attempt but not the file transfer itself.

## Assessment

This dataset provides moderate value for detection engineering, primarily demonstrating how endpoint protection can prevent LOLBin abuse. The Security 4688 events with command-line logging capture the malicious intent clearly, making this technique detectable even when blocked. However, the dataset's utility is limited by the fact that the technique was prevented rather than executed, so it doesn't show the full attack chain or network activity patterns.

The presence of process injection events and extensive PowerShell module loading provides context about the execution environment, but the core T1105 technique evidence resides entirely in the blocked command-line execution. For building detections of successful MpCmdRun.exe abuse, analysts would need complementary datasets where the technique executes successfully.

## Detection Opportunities Present in This Data

1. **Command-line detection for MpCmdRun.exe abuse** - Security EID 4688 showing `MpCmdRun.exe -DownloadFile` with external URLs
2. **Process exit status monitoring** - Security EID 4689 showing cmd.exe termination with STATUS_ACCESS_DENIED (0xC0000022)
3. **Suspicious parent-child relationships** - PowerShell spawning cmd.exe to execute Windows Defender utilities
4. **Directory traversal patterns** - Command-lines using wildcard expansion to locate Windows Defender platform directories
5. **Process injection from PowerShell** - Sysmon EID 8 showing CreateRemoteThread activity from PowerShell processes
6. **PowerShell privilege escalation** - Security EID 4703 showing token privilege adjustments for system-level access
