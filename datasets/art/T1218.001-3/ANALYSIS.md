# T1218.001-3: Compiled HTML File — Invoke CHM with default Shortcut Command Execution

## Technique Context

T1218.001 (Compiled HTML File) is a defense evasion technique where attackers leverage the HTML Help executable (hh.exe) to proxy execution of malicious code. Compiled HTML Help files (.chm) can contain embedded scripts, executables, or other content that executes when the CHM file is opened. This technique is particularly valuable to attackers because hh.exe is a signed Microsoft binary that may bypass application whitelisting controls and appears legitimate to security tools.

The detection community focuses on monitoring hh.exe process creation, especially when launched with suspicious command-line arguments or from unusual parent processes. Key indicators include hh.exe spawning child processes, network connections from hh.exe, or hh.exe loading unexpected DLLs. The technique often appears in phishing campaigns where malicious CHM files are distributed as attachments.

## What This Dataset Contains

This dataset captures a PowerShell-based execution of the CHM technique but notably **does not contain the critical hh.exe process creation**. The Security channel shows PowerShell process creation with the command line `"powershell.exe" & {Invoke-ATHCompiledHelp -HHFilePath $env:windir\hh.exe -CHMFilePath Test.chm}` (EID 4688, Process ID 13820), indicating the test attempted to invoke hh.exe with a CHM file.

The PowerShell script block logging captures the test function invocation: `& {Invoke-ATHCompiledHelp -HHFilePath $env:windir\hh.exe -CHMFilePath Test.chm}` and `{Invoke-ATHCompiledHelp -HHFilePath $env:windir\hh.exe -CHMFilePath Test.chm}` (EID 4104).

Sysmon captures standard PowerShell process activity including:
- Process creation for powershell.exe (EID 1, Process ID 13820) with the full command line showing the CHM invocation attempt
- Process creation for whoami.exe (EID 1, Process ID 20312), suggesting some payload execution occurred
- Standard .NET runtime image loads for PowerShell processes (EID 7)
- PowerShell named pipe creation (EID 17)
- Process access events showing PowerShell accessing the whoami.exe and child PowerShell processes (EID 10)

## What This Dataset Does Not Contain

Most critically, **this dataset lacks any hh.exe process creation events**. Neither Sysmon EID 1 nor Security EID 4688 show hh.exe launching, which should be the primary telemetry for this technique. This absence suggests either:

1. Windows Defender blocked the hh.exe execution before process creation
2. The CHM file was malformed or missing
3. The test framework failed to properly invoke hh.exe
4. The sysmon-modular configuration filtered out hh.exe (though hh.exe should match LOLBin patterns)

The dataset also lacks:
- File creation events for the Test.chm file
- Network connections that might result from CHM payload execution
- Registry modifications often associated with CHM exploitation
- Any child processes spawned by hh.exe (which would be the actual malicious payload execution)

## Assessment

This dataset has **limited utility** for detection engineering of T1218.001. While it captures the PowerShell test framework attempting to invoke the CHM technique, it lacks the core telemetry that defenders need to detect actual CHM abuse. The absence of hh.exe process creation makes this dataset unsuitable for testing detections focused on the primary attack vector.

The dataset is more valuable for understanding test framework behavior and PowerShell-based technique invocation than for the CHM technique itself. The whoami.exe execution suggests some payload ran, but without the hh.exe process chain, it's unclear how this relates to CHM exploitation.

## Detection Opportunities Present in This Data

1. **PowerShell command line analysis** - Detect PowerShell executing with command lines containing references to hh.exe and .chm files, particularly with function names like "Invoke-ATHCompiledHelp"

2. **PowerShell script block monitoring** - Alert on PowerShell script blocks invoking hh.exe with CHM file parameters, even when the actual execution fails

3. **Unexpected process relationships** - Monitor for PowerShell processes spawning whoami.exe or other reconnaissance tools, which may indicate successful payload execution via alternative methods

4. **PowerShell process access patterns** - Detect PowerShell processes accessing newly created child processes with full access rights (0x1FFFFF), which may indicate process injection or monitoring behavior

5. **Failed technique execution patterns** - Create detection logic for PowerShell-based test frameworks attempting to execute LOLBin techniques, which can indicate red team activity or malware testing phases
