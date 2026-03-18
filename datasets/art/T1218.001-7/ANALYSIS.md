# T1218.001-7: Compiled HTML File — Invoke CHM Shortcut Command with ITS and Help Topic

## Technique Context

T1218.001 (Compiled HTML File) is a defense evasion technique where attackers abuse the Microsoft HTML Help executable (hh.exe) to proxy execution of malicious code. HTML Help files (.chm) can contain embedded objects like ActiveX controls, JavaScript, or VBScript that execute when the help file is opened. This technique is particularly valuable to attackers because hh.exe is a signed Microsoft binary that can bypass application whitelisting controls and execute content from CHM files. The detection community typically focuses on monitoring hh.exe process creation, unusual command-line arguments (especially with ms-its: protocol handlers), network connections from hh.exe, and child processes spawned by the HTML Help system.

## What This Dataset Contains

This dataset captures a PowerShell-based test that attempts to execute a CHM file using the ITS (InfoTech Storage) protocol handler. The key evidence includes:

**PowerShell Script Block Logging (EID 4104):** The core technique execution is captured in script block ID 79931f6b-cb25-41b0-97d5-ee0af32afc60: `& {Invoke-ATHCompiledHelp -ExecuteShortcutCommand -InfoTechStorageHandler its -TopicExtension html -HHFilePath $env:windir\hh.exe -CHMFilePath Test.chm}`

**Process Creation (Security EID 4688):** Shows the PowerShell child process created to execute the technique: `"powershell.exe" & {Invoke-ATHCompiledHelp -ExecuteShortcutCommand -InfoTechStorageHandler its -TopicExtension html -HHFilePath $env:windir\hh.exe -CHMFilePath Test.chm}` (Process ID 0x65ac)

**Sysmon Process Creation (EID 1):** Provides additional detail on the child PowerShell process (Process ID 26028) with full command line visibility and process relationship mapping.

**Process Access Events (Sysmon EID 10):** Multiple process access events show PowerShell processes accessing other processes with full access rights (0x1FFFFF), including access to whoami.exe (Process ID 25432) and the child PowerShell process.

**Supporting Process Activity:** The dataset includes a whoami.exe execution (Sysmon EID 1, Process ID 25432) with command line `"C:\Windows\system32\whoami.exe"`, likely part of the test framework's validation.

## What This Dataset Does Not Contain

The dataset lacks the most critical evidence for T1218.001 detection - **there are no hh.exe process creation events**. This suggests that either:
1. Windows Defender blocked the hh.exe execution before it could start
2. The CHM file referenced ("Test.chm") may not have existed in the execution directory
3. The Invoke-ATHCompiledHelp function encountered an error during execution

Additionally missing:
- **Sysmon ProcessCreate events for hh.exe** (the sysmon-modular config includes hh.exe in its LOLBin detection rules, so these should have been captured if the process launched)
- **Network connections** that might indicate CHM content attempting to download additional payloads
- **File creation events** for temporary files that CHM execution typically generates
- **Registry modifications** that HTML Help system interactions often produce

## Assessment

This dataset has **limited utility** for T1218.001 detection engineering because it captures only the attempt to execute the technique, not the actual technique execution. The PowerShell telemetry is valuable for detecting the specific Atomic Red Team test methodology and PowerShell-based CHM invocation attempts, but defenders primarily need to detect successful hh.exe abuse rather than just the setup commands. The process access events provide some behavioral context, but the absence of hh.exe execution significantly reduces the dataset's value for understanding the full attack chain. This dataset would be most useful for detecting reconnaissance or setup phases of CHM-based attacks rather than the execution itself.

## Detection Opportunities Present in This Data

1. **PowerShell CHM invocation detection** - Monitor for PowerShell script blocks containing "hh.exe", "CHMFilePath", "InfoTechStorageHandler", or "ms-its:" protocol references in EID 4104 events

2. **Atomic Red Team framework detection** - Alert on PowerShell execution containing "Invoke-ATHCompiledHelp" function calls as indicators of security testing activity

3. **PowerShell child process spawning** - Detect PowerShell processes creating additional PowerShell children with CHM-related command line arguments in Security EID 4688 events

4. **Suspicious process access patterns** - Monitor for PowerShell processes accessing multiple targets with full access rights (0x1FFFFF) in Sysmon EID 10, especially when combined with CHM-related activity

5. **PowerShell execution policy bypass detection** - Flag "Set-ExecutionPolicy Bypass" commands in PowerShell EID 4103 events when occurring in proximity to CHM-related activity

6. **Command line analysis for CHM abuse attempts** - Search for command lines containing combinations of PowerShell, hh.exe paths, and .chm file references across Security EID 4688 events
