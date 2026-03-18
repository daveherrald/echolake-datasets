# T1083-9: File and Directory Discovery — Recursive Enumerate Files And Directories By Powershell

## Technique Context

T1083 (File and Directory Discovery) is a fundamental discovery technique where adversaries enumerate files and directories to understand the target system's structure and locate valuable data. This technique is commonly used during the initial reconnaissance phase of an attack to identify documents, credentials, configuration files, and other sensitive information that could aid in lateral movement or data exfiltration.

PowerShell-based file enumeration is particularly attractive to adversaries because it provides native system capabilities without requiring additional tools. The technique often involves recursive directory traversal with filtering for specific file types (documents, archives, databases) and can include gathering metadata like file sizes and modification timestamps. Detection engineers focus on monitoring for PowerShell execution with file system enumeration patterns, particularly when targeting user profile directories or scanning for sensitive file extensions.

## What This Dataset Contains

This dataset captures a sophisticated PowerShell-based file discovery script executed as a child process. The main evidence appears in Security 4688 events showing the PowerShell command line with the complete enumeration script:

```powershell
"powershell.exe" & {$out = "$env:TEMP\T1083-Enumerate-net.txt"
$dirsFilter = @('Documents','Downloads','Desktop','OneDrive')
$exts = @('.pdf','.doc','.docx','.xls','.xlsx','.txt','.zip','.rar','.7z')
$userProfile = [Environment]::GetFolderPath('UserProfile')
...
```

The script implements a recursive directory scanner that filters for specific directories (Documents, Downloads, Desktop, OneDrive) and file extensions commonly associated with valuable data. PowerShell events (EID 4104) capture extensive script block logging showing the actual execution, including ForEach-Object invocations with specific file paths being processed like `C:\Windows\system32\config\systemprofile\Desktop\AppDataBackup.zip` and various browser-related files.

Sysmon EID 1 events capture process creation for both the parent PowerShell test framework (PID 37428) and the child PowerShell process executing the enumeration script (PID 20164). The Sysmon EID 11 file creation event shows the output file being written to `C:\Windows\Temp\T1083-Enumerate-net.txt`. Additionally, Sysmon EID 10 process access events document the parent process monitoring its child during execution.

## What This Dataset Does Not Contain

The dataset lacks visibility into the actual enumerated results since the output file contents aren't captured in the logs. Network-based exfiltration of discovered files would not be visible as no network connections were established. The script only enumerates existing files on the system profile rather than user directories that might contain more realistic target data.

Since this is a controlled test environment, it doesn't show the technique being used against a realistic user environment with actual sensitive documents. The sysmon-modular configuration's process filtering means we don't see all potential child processes that might be spawned during file operations, though in this case the enumeration was performed entirely within PowerShell.

## Assessment

This dataset provides excellent coverage of PowerShell-based file discovery techniques. The combination of Security 4688 events with full command-line logging, comprehensive PowerShell script block logging (4104), and Sysmon process/file creation events creates multiple detection opportunities. The complete PowerShell script is preserved in the command line, making this particularly valuable for signature-based detection development.

The PowerShell telemetry is especially rich, showing not just the script execution but also the detailed ForEach-Object operations and file paths being processed. This level of visibility supports both behavioral analysis (looking for enumeration patterns) and content-based detection (identifying suspicious file extension lists or directory filters).

However, the synthetic nature of the environment limits the realism of the data being enumerated, and the absence of follow-on activities (like data staging or exfiltration) means this captures only the discovery phase of a typical attack chain.

## Detection Opportunities Present in This Data

1. **PowerShell command-line analysis** - Security EID 4688 contains the complete enumeration script with suspicious file extension arrays (.pdf, .doc, .docx, .xls, .xlsx, .txt, .zip, .rar, .7z) and directory filters targeting user data locations

2. **Script block content detection** - PowerShell EID 4104 events show script blocks containing file enumeration functions, recursive directory scanning logic, and calls to System.IO.Directory.EnumerateFiles and EnumerateDirectories APIs

3. **Behavioral pattern recognition** - Multiple PowerShell EID 4103 CommandInvocation events for ForEach-Object operations processing numerous file paths in sequence indicate automated file system traversal

4. **Output file creation monitoring** - Sysmon EID 11 shows creation of results file in temp directory with technique-specific naming pattern (T1083-Enumerate-net.txt)

5. **Process relationship analysis** - Sysmon EID 1 and EID 10 events reveal parent-child PowerShell process relationships with the parent monitoring child execution, indicating programmatic control

6. **File system enumeration indicators** - PowerShell events contain numerous file paths being processed, particularly targeting browser data directories and user profile locations, indicating systematic file discovery rather than normal access patterns

7. **Suspicious PowerShell API usage** - Script blocks show use of System.IO.FileInfo class instantiation and file metadata collection (Length, LastWriteTime) suggesting data reconnaissance rather than legitimate file operations
