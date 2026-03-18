# T1218.005-9: Mshta — Invoke HTML Application - Simulate Lateral Movement over UNC Path

## Technique Context

T1218.005 (Mshta) is a defense evasion technique where attackers abuse the Microsoft HTML Application Host (mshta.exe) to execute malicious scripts and bypass application controls. Mshta.exe is a legitimate Windows utility that can execute HTML Applications (.hta files) containing VBScript or JScript, making it an attractive LOLBin for attackers. This specific test simulates lateral movement by creating and executing an HTA file via a local UNC path, which mimics how attackers might distribute malicious HTA files across a network.

The detection community focuses on unusual mshta.exe command lines, network connections to suspicious locations, process ancestry chains involving mshta, and the creation/execution of HTA files from temporary or network locations. Key indicators include mshta executing files from UNC paths, spawning unexpected child processes, or loading content from suspicious URLs.

## What This Dataset Contains

This dataset captures the PowerShell execution of the Invoke-ATHHTMLApplication function but notably lacks the actual mshta.exe process execution. The key telemetry includes:

**PowerShell Script Execution:** Security event 4688 shows the PowerShell command that would execute the test: `"powershell.exe" & {Invoke-ATHHTMLApplication -TemplatePE -AsLocalUNCPath -MSHTAFilePath $env:windir\system32\mshta.exe}`. PowerShell script block logging (EID 4104) captures the same command execution.

**Process Chain:** The execution starts from a parent PowerShell process (PID 11752) which spawns a child PowerShell process (PID 3504) with the specific Invoke-ATHHTMLApplication command line.

**System Discovery Activity:** Sysmon EID 1 shows the execution of whoami.exe with the command line `"C:\Windows\system32\whoami.exe"`, indicating the test framework performed system user discovery as part of the simulation.

**PowerShell Telemetry:** Extensive Sysmon EID 7 events show .NET runtime and PowerShell module loading across multiple PowerShell processes, indicating the framework's initialization and execution.

## What This Dataset Does Not Contain

This dataset is missing the core technique evidence - **there are no events showing mshta.exe process creation or execution**. The Sysmon process creation events only capture whoami.exe and PowerShell processes, suggesting either:

1. The sysmon-modular config's include-mode filtering for ProcessCreate (EID 1) doesn't match mshta.exe patterns
2. Windows Defender blocked the mshta.exe execution before it could start
3. The Atomic Red Team test failed to actually execute mshta.exe

Additionally missing:
- No HTA file creation events (Sysmon EID 11 only shows PowerShell profile files)
- No network connections or DNS queries from mshta.exe
- No suspicious child processes spawned by mshta.exe
- No registry modifications typical of HTA execution

## Assessment

This dataset has **limited value** for T1218.005 detection engineering because it lacks the primary technique execution telemetry. While it captures the PowerShell command that would invoke mshta, the absence of actual mshta.exe process creation severely limits its utility for building mshta-specific detections.

The dataset is more valuable for understanding PowerShell-based attack frameworks and their command patterns. The PowerShell script block logging and command-line auditing provide good coverage of the preparation phase, but detection engineers need actual mshta execution telemetry to develop effective rules for this technique.

The whoami.exe execution provides some secondary value for post-exploitation discovery activity detection, but this is tangential to the core T1218.005 technique.

## Detection Opportunities Present in This Data

1. **PowerShell Command Line Analysis** - Security EID 4688 and PowerShell EID 4104 showing "Invoke-ATHHTMLApplication" function calls with mshta-related parameters

2. **Suspicious PowerShell Process Chains** - Parent/child PowerShell relationships where the child process has mshta-related command lines

3. **System Discovery After Script Execution** - Correlation of PowerShell execution followed by whoami.exe process creation within short time windows

4. **PowerShell Framework Detection** - Process trees showing PowerShell spawning system utilities like whoami.exe, which may indicate automated attack framework execution

5. **Script Block Logging for Attack Frameworks** - PowerShell EID 4104 events containing "ATH" or "Atomic" strings indicating test framework usage
