# T1119-1: Automated Collection — Automated Collection Command Prompt

## Technique Context

T1119 Automated Collection represents adversaries using automated methods to collect files of interest from a compromised system. This technique is particularly concerning because it enables rapid, systematic collection of sensitive data without manual intervention. Attackers commonly use this approach after establishing initial access to efficiently harvest valuable information before exfiltration.

The detection community focuses on identifying patterns of bulk file operations, unusual file system traversal behaviors, and the creation of staging directories where collected files are temporarily stored. Command-line tools like `dir`, `findstr`, and `copy` are frequently abused for this purpose, making process monitoring and command-line analysis critical detection vectors.

## What This Dataset Contains

This dataset captures a complete automated collection sequence executed via PowerShell and command prompt. The primary evidence includes:

**Process Chain**: Security event 4688 shows PowerShell spawning cmd.exe with the command: `"cmd.exe" /c mkdir %temp%\T1119_command_prompt_collection >nul 2>&1 & dir c: /b /s .docx | findstr /e .docx & for /R c:\ %f in (*.docx) do copy /Y %f %temp%\T1119_command_prompt_collection`

**File Discovery Operations**: Sysmon events capture the process tree showing cmd.exe (PID 25580) spawning:
- A child cmd.exe (PID 16372) executing `dir c: /b /s .docx` for recursive directory listing
- findstr.exe (PID 12344) with `findstr /e .docx` to filter results

**File Collection Evidence**: Sysmon event 11 shows two file creation events for `C:\Windows\Temp\T1119_command_prompt_collection\T1218Test.docx`, indicating successful collection of a .docx file into the staging directory.

**Supporting Telemetry**: The dataset includes comprehensive Sysmon coverage (events 1, 7, 10, 11, 17) showing process creation, image loads, process access, file operations, and pipe creation. PowerShell script block logging (event 4104) captures execution policy bypass commands.

## What This Dataset Does Not Contain

The dataset lacks network exfiltration events that would typically follow automated collection. While files are collected into a staging directory, there's no evidence of subsequent data transfer or communication with external systems. Additionally, the sysmon-modular configuration's include-mode filtering means some intermediate process creations may not be captured, though the Security channel's 4688 events provide complementary coverage with complete command-line logging.

The PowerShell events primarily contain test framework boilerplate rather than the actual collection logic, which appears to be implemented entirely through the spawned cmd.exe processes.

## Assessment

This dataset provides excellent visibility into automated collection techniques executed through command-line utilities. The combination of Security 4688 events with full command-line logging and Sysmon process creation events offers multiple detection opportunities. The file creation events (Sysmon 11) provide direct evidence of the collection outcome, while the process tree clearly shows the systematic approach used for file discovery and copying.

The telemetry quality is high for building detections around bulk file operations, staging directory creation, and suspicious command-line patterns. The presence of both process and file system artifacts makes this dataset particularly valuable for developing layered detection approaches.

## Detection Opportunities Present in This Data

1. **Staging Directory Creation**: Monitor for mkdir commands creating temporary directories with suspicious naming patterns like "collection" or "gather" in command lines.

2. **Bulk File Discovery Commands**: Detect recursive directory listing operations using `dir /s /b` combined with file extension filtering, especially when targeting document types (.docx, .pdf, .xlsx).

3. **Findstr File Filtering**: Alert on findstr.exe usage with `/e` parameter filtering for specific file extensions, particularly when part of a process chain involving directory enumeration.

4. **Batch File Copy Operations**: Monitor for `copy` commands with `/Y` parameter in loops or combined with directory traversal operations, especially when targeting user-created files.

5. **Process Chain Analysis**: Detect cmd.exe spawning multiple child processes for file system operations in sequence (dir -> findstr -> copy pattern).

6. **File System Write Anomalies**: Alert on rapid file creation events in temporary directories, particularly when files are copied from diverse source locations.

7. **Command-Line Pattern Matching**: Detect compound commands using `&` or `|` operators that combine directory listing, filtering, and file copying operations in a single execution.

8. **PowerShell-to-CMD Spawning**: Monitor for PowerShell processes spawning cmd.exe with complex command-line arguments containing file system operations.
