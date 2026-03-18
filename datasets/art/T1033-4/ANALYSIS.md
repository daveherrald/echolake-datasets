# T1033-4: System Owner/User Discovery — User Discovery With Env Vars PowerShell Script

## Technique Context

T1033 System Owner/User Discovery is a fundamental Discovery technique where adversaries attempt to identify the current user context, domain information, and system ownership details. This information helps attackers understand their privilege level, plan privilege escalation paths, and determine lateral movement opportunities. The technique is commonly observed early in the attack lifecycle as part of initial reconnaissance.

This specific test (T1033-4) demonstrates user discovery through PowerShell environment variables, using both `[System.Environment]::UserName` and `$env:UserName` to capture user information. The detection community typically focuses on PowerShell script block logging, command-line arguments containing user enumeration patterns, and the creation of files containing user information. This approach represents a common post-exploitation technique where attackers use built-in .NET classes and PowerShell environment variables to avoid calling external binaries.

## What This Dataset Contains

The dataset captures a PowerShell-based user discovery technique that creates a file containing user information. The key evidence includes:

**PowerShell Script Block Logging (EID 4104):** The actual technique execution is captured in PowerShell script block `ec4512bc-18ce-40cb-a032-713fd7566cc8`: `"& {[System.Environment]::UserName | Out-File -FilePath .\CurrentactiveUser.txt $env:UserName | Out-File -FilePath .\CurrentactiveUser.txt -Append}"`. The script uses two methods to retrieve username information and outputs both to the same file.

**Command-Line Evidence (Security EID 4688):** Process creation event shows: `"powershell.exe" & {[System.Environment]::UserName | Out-File -FilePath .\CurrentactiveUser.txt $env:UserName | Out-File -FilePath .\CurrentactiveUser.txt -Append}` launched by the parent PowerShell process.

**PowerShell Command Invocation (EID 4103):** Two Out-File cmdlet invocations are captured, showing `InputObject` values of "SYSTEM" and "ACME-WS02$", revealing the actual user context information being collected.

**File Creation (Sysmon EID 11):** The creation of `C:\Windows\Temp\CurrentactiveUser.txt` at `2026-03-13 17:29:44.647` by the PowerShell process, representing the technique's output artifact.

**Process Chain:** The execution shows typical ART test framework behavior with multiple PowerShell processes and a whoami.exe execution for comparison, running under NT AUTHORITY\SYSTEM context.

## What This Dataset Does Not Contain

The dataset is missing several important elements typically associated with this technique. There are no Sysmon ProcessCreate events (EID 1) for the initial PowerShell processes due to the sysmon-modular configuration's include-mode filtering, which only captures processes matching known-suspicious patterns. The PowerShell channel contains mostly test framework boilerplate scripts rather than the actual technique payload in script blocks. Network connections or DNS queries that might accompany user discovery in real scenarios are absent. Registry queries that attackers often perform alongside user enumeration are not captured, and there's no evidence of the technique attempting to discover domain context or group memberships beyond the basic username.

## Assessment

This dataset provides solid coverage for detecting PowerShell-based user discovery through environment variables. The combination of PowerShell script block logging (EID 4104), command invocation logging (EID 4103), and Security process creation events (EID 4688) creates multiple detection opportunities. The file creation telemetry (Sysmon EID 11) adds valuable IOC data for hunting activities. However, the dataset would be stronger with network telemetry showing potential data exfiltration, registry access events showing additional enumeration attempts, and more diverse user contexts beyond SYSTEM execution. The technique executes successfully without Windows Defender interference, providing clean telemetry for detection engineering.

## Detection Opportunities Present in This Data

1. **PowerShell Script Block Pattern Matching** - Detect script blocks containing `[System.Environment]::UserName` or `$env:UserName` combined with `Out-File` cmdlets, indicating programmatic user discovery attempts.

2. **Command-Line User Discovery Patterns** - Monitor Security EID 4688 events for PowerShell processes with command lines containing user enumeration patterns like `Environment::UserName` and file output redirections.

3. **PowerShell Cmdlet Invocation Sequences** - Alert on PowerShell EID 4103 events showing Out-File cmdlets with suspicious filenames like "CurrentactiveUser.txt" or similar user information collection patterns.

4. **File Creation in Temporary Locations** - Monitor Sysmon EID 11 for text files created in temp directories with names suggesting user information collection (e.g., patterns matching "*user*.txt", "*current*.txt").

5. **PowerShell Process Ancestry Analysis** - Detect PowerShell child processes spawned from parent PowerShell with command lines containing both .NET Environment class calls and environment variable access.

6. **Suspicious File Output Combinations** - Correlate PowerShell script execution with immediate file creation events in the same process context, especially when filenames suggest data collection purposes.

7. **Multi-Method User Enumeration** - Identify scripts that use multiple user discovery methods (both .NET classes and environment variables) within the same execution context, indicating thorough reconnaissance attempts.
