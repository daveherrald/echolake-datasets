# T1027-4: Obfuscated Files or Information — Execution from Compressed File

## Technique Context

T1027.004 focuses on adversaries executing malicious payloads directly from compressed archives (ZIP, RAR, 7z, etc.) without extracting them to disk first. This technique provides defense evasion benefits by avoiding file system artifacts that static analysis tools and endpoint protection solutions typically scan. Modern operating systems and applications can execute code directly from memory-mapped compressed files, making this an attractive technique for malware delivery and initial access scenarios.

The detection community primarily focuses on monitoring for processes spawned with command lines referencing compressed file paths, unusual parent-child process relationships where executables appear to run from archive locations, and file system events showing temporary extraction of executables from archives. PowerShell's `Expand-Archive` cmdlet and native Windows extraction utilities are common legitimate tools that can be abused for this technique.

## What This Dataset Contains

This dataset captures PowerShell executing a binary (`T1027.exe`) directly from within a ZIP archive located at `C:\AtomicRedTeam\atomics\..\ExternalPayloads\temp_T1027.zip\T1027.exe`. The key evidence appears in Security event 4688 showing cmd.exe being spawned with the command line `"cmd.exe" /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\temp_T1027.zip\T1027.exe"`. The Sysmon EID 1 event provides additional process creation details, showing cmd.exe (PID 4428) created by powershell.exe with the same command line attempting to execute the file from within the compressed archive.

The dataset shows the execution attempt failed, as evidenced by Security event 4689 showing cmd.exe exiting with status 0x1 (error). The PowerShell events contain only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) and error handling scriptblocks, with no technique-specific PowerShell commands captured.

Notable supporting events include Sysmon EID 10 process access events showing PowerShell accessing both whoami.exe and cmd.exe processes, likely related to PowerShell's process management during execution attempts.

## What This Dataset Does Not Contain

The dataset lacks evidence of successful execution from the compressed file - the cmd.exe process exits with error code 1, indicating the technique failed to execute properly. There are no file extraction events (Sysmon EID 11) showing temporary files being created from the archive, no network connections, and no evidence of the actual `T1027.exe` payload running successfully.

The PowerShell script block logs don't contain the actual Atomic Red Team test commands that would show how the compressed file execution was attempted, only containing framework boilerplate. There are also no registry modifications or additional file system artifacts that would indicate successful payload deployment.

## Assessment

This dataset provides limited utility for detection engineering because it captures a failed execution attempt rather than successful technique implementation. While the command line artifacts showing execution from within a ZIP path are valuable detection indicators, the lack of successful execution means defenders won't see the full attack chain or post-execution behaviors.

The Security 4688 and Sysmon EID 1 events do demonstrate the key detection opportunity - processes spawned with command lines referencing files within compressed archives. However, the failure of the technique means this dataset won't help defenders understand what successful compressed file execution looks like in their environment or test detection rules against working implementations.

## Detection Opportunities Present in This Data

1. **Command Line Analysis**: Monitor Security 4688 and Sysmon EID 1 events for command lines containing paths with archive file extensions followed by subdirectories (e.g., `*.zip\*`, `*.rar\*`, `*.7z\*`)

2. **Process Chain Anomalies**: Alert on cmd.exe or other system utilities spawned with command lines attempting to execute files from within archive paths, particularly when the parent process is PowerShell or other scripting engines

3. **Failed Execution Patterns**: Monitor for processes exiting with error codes (Security EID 4689) when command lines reference archive-internal file paths, as this may indicate blocked or failed compressed file execution attempts

4. **Parent-Child Process Relationships**: Detect PowerShell spawning cmd.exe with command lines referencing compressed file locations, especially when combined with subsequent process access events (Sysmon EID 10)

5. **PowerShell Execution Policy Changes**: While not technique-specific, the Set-ExecutionPolicy Bypass commands in PowerShell logs can indicate preparation for potentially malicious script execution that may include compressed file operations
