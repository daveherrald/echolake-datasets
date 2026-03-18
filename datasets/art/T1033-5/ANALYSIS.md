# T1033-5: System Owner/User Discovery — GetCurrent User with PowerShell Script

## Technique Context

T1033 System Owner/User Discovery is a fundamental reconnaissance technique where adversaries identify the current user context of their execution environment. This information helps attackers understand their privilege level, determine lateral movement opportunities, and tailor subsequent actions. The technique is particularly common in initial access scenarios and privilege escalation attempts.

This specific test (T1033-5) demonstrates using PowerShell's `[System.Security.Principal.WindowsIdentity]::GetCurrent()` .NET method to retrieve detailed information about the current user's security principal. Unlike simpler commands like `whoami`, this approach provides programmatic access to the full Windows identity object, including security identifiers, authentication type, and token information. Detection engineers focus on PowerShell script block logging, .NET method invocations, and the characteristic API calls this technique generates.

## What This Dataset Contains

The dataset captures a complete execution of the PowerShell-based user discovery technique. The core activity appears in Security event 4688 showing PowerShell spawning with the command line `"powershell.exe" & {[System.Security.Principal.WindowsIdentity]::GetCurrent() | Out-File -FilePath .\CurrentUserObject.txt}`.

PowerShell logging captured the technique execution through multiple events:
- Script block 4104 events showing the actual technique: `& {[System.Security.Principal.WindowsIdentity]::GetCurrent() | Out-File -FilePath .\CurrentUserObject.txt}`
- Command invocation 4103 event logging the `Out-File` cmdlet with parameter binding showing `FilePath: .\CurrentUserObject.txt`
- Additional script blocks for `{[System.Security.Principal.WindowsIdentity]::GetCurrent() | Out-File -FilePath .\CurrentUserObject.txt}`

Sysmon provides detailed process telemetry including:
- Process creation (EID 1) for both the PowerShell process (PID 1924) and a `whoami.exe` execution (PID 1336)
- File creation (EID 11) showing the output file `C:\Windows\Temp\CurrentUserObject.txt` being written
- Process access events (EID 10) showing PowerShell accessing the whoami.exe process with full access rights (0x1FFFFF)
- Extensive .NET runtime DLL loading events as PowerShell initializes the execution environment

The process chain shows: Initial PowerShell → Secondary PowerShell (PID 1924) executing the discovery script → whoami.exe (PID 1336) for additional user enumeration.

## What This Dataset Does Not Contain

The dataset lacks the actual content of the output file `CurrentUserObject.txt`, which would contain the serialized WindowsIdentity object with detailed user information. File content monitoring would be needed to capture the data exfiltration aspect.

Most PowerShell events consist of test framework boilerplate (`Set-StrictMode -Version 1` scriptblocks and `Set-ExecutionPolicy Bypass` commands) rather than attack-specific content. The sysmon-modular configuration's include-mode filtering for ProcessCreate explains why we see the whoami.exe process but might miss other spawned utilities.

The dataset doesn't show any network activity that might occur if this technique were part of a broader reconnaissance campaign involving data transmission. Windows Defender was active but didn't block this technique, as it represents legitimate PowerShell functionality being used for discovery.

## Assessment

This dataset provides excellent coverage for detecting PowerShell-based user discovery techniques. The combination of Security audit logs with full command-line logging, comprehensive PowerShell script block logging, and detailed Sysmon telemetry creates multiple detection opportunities. The technique generated clear, unambiguous evidence across multiple data sources.

The presence of both the .NET method call and the traditional whoami.exe execution provides detection engineers with examples of how attackers might combine different approaches. The file creation events showing the output location add another detection vector. However, the dataset would be stronger with file content monitoring to capture what information was actually extracted.

## Detection Opportunities Present in This Data

1. **PowerShell Script Block Analysis**: Monitor EID 4104 for `System.Security.Principal.WindowsIdentity::GetCurrent()` method invocations in script blocks, particularly when combined with output redirection or file operations.

2. **Command Line Pattern Matching**: Detect Security EID 4688 events with PowerShell command lines containing the characteristic .NET identity method calls and file output patterns.

3. **Process-File Correlation**: Alert on PowerShell processes (Sysmon EID 1) followed immediately by file creation events (EID 11) with suspicious filenames like "CurrentUserObject.txt" or similar naming patterns.

4. **PowerShell Cmdlet Monitoring**: Track PowerShell EID 4103 command invocation events for `Out-File` cmdlets with file paths that suggest user enumeration data collection.

5. **Cross-Process Access Patterns**: Monitor Sysmon EID 10 for PowerShell processes accessing system utilities like whoami.exe with high-privilege access rights, indicating potential process injection or debugging attempts.

6. **Behavioral Process Chaining**: Detect sequences where PowerShell spawns secondary PowerShell instances executing discovery commands, combined with system utility execution like whoami.exe.

7. **File System Artifacts**: Monitor for file creation in temporary directories with names suggesting user identity or security principal data collection activities.
