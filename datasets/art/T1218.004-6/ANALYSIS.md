# T1218.004-6: InstallUtil — InstallUtil Uninstall method call - '/installtype=notransaction /action=uninstall' variant

## Technique Context

T1218.004 (InstallUtil) is a defense evasion technique where attackers abuse the legitimate Microsoft .NET InstallUtil.exe binary to execute arbitrary code. InstallUtil is designed to install and uninstall server resources by executing installer components in managed assemblies. Attackers can craft malicious installer assemblies that contain code in constructors or specific methods (Install, Uninstall, Commit, Rollback) that gets executed when InstallUtil processes the assembly.

The detection community focuses on monitoring InstallUtil.exe execution with unusual command lines, especially when it processes assemblies from temporary directories or with suspicious names. This specific test variant uses the "/action=uninstall" and "/installtype=notransaction" parameters to trigger the Uninstall method execution, representing a common evasion pattern where attackers use less common InstallUtil switches to avoid basic detections.

## What This Dataset Contains

The dataset captures a complete InstallUtil evasion workflow executed through PowerShell automation. The key evidence includes:

**Process Creation Chain**: Security EID 4688 shows the complete process lineage: PowerShell spawning a child PowerShell process that creates two C# compiler processes (csc.exe) and finally launches InstallUtil.exe with the command line `"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe" /logfile= /logtoconsole=false /installtype=notransaction /action=uninstall C:\Windows\TEMP\T1218.004.dll`.

**Assembly Compilation**: Sysmon EID 1 captures csc.exe executions with command lines referencing temporary cmdline files (`@"C:\Windows\SystemTemp\k3kc0kio\k3kc0kio.cmdline"` and `@"C:\Windows\SystemTemp\y12f1fny\y12f1fny.cmdline"`), showing the dynamic C# assembly compilation that precedes the InstallUtil execution.

**File System Artifacts**: Sysmon EID 11 events document the creation of compilation artifacts including the target assembly `C:\Windows\Temp\T1218.004.dll`, temporary source files with `.cs` extensions, and various compiler output files in SystemTemp directories.

**PowerShell Context**: PowerShell EID 4104 script blocks reveal the test framework importing InstallUtilTestHarness.ps1 and calling `Invoke-BuildAndInvokeInstallUtilAssembly` with the uninstall parameters, providing context for the technique execution.

## What This Dataset Does Not Contain

The dataset lacks several important detection artifacts. The actual InstallUtil.exe process creation is missing from Sysmon EID 1 events, likely because the sysmon-modular configuration's include-mode filtering doesn't capture InstallUtil.exe as a monitored binary despite it being a known LOLBin. The .NET assembly loading events that would show InstallUtil loading and executing the malicious T1218.004.dll are also absent from the image load telemetry.

Network connections, registry modifications, or other persistence mechanisms that might result from successful InstallUtil code execution are not present, suggesting this test focused solely on process execution validation rather than post-exploitation activities.

## Assessment

This dataset provides strong telemetry for detecting InstallUtil abuse through process monitoring and file system analysis. The Security channel's command-line auditing captures the critical InstallUtil execution with suspicious parameters, while Sysmon file creation events document the assembly compilation workflow. However, the missing Sysmon process creation for InstallUtil.exe itself represents a significant gap - detection engineers would need to rely on Security EID 4688 events rather than the richer Sysmon telemetry for process-based detections.

The PowerShell script block logging provides excellent context for understanding how the technique was orchestrated, making this dataset valuable for threat hunting scenarios where analysts need to understand the full attack chain.

## Detection Opportunities Present in This Data

1. **InstallUtil Command Line Detection** - Security EID 4688 with command line containing "InstallUtil.exe" combined with suspicious flags like "/action=uninstall", "/installtype=notransaction", and assemblies from temp directories

2. **Dynamic Assembly Compilation** - Sysmon EID 1 showing csc.exe execution with command lines referencing temporary cmdline files, indicating on-the-fly malicious assembly creation

3. **Temp Directory Assembly Creation** - Sysmon EID 11 file creation events for .dll files in Windows temp directories followed by InstallUtil execution against those same files

4. **Process Chain Analysis** - Security EID 4688 showing PowerShell spawning csc.exe processes followed by InstallUtil.exe execution, indicating automated InstallUtil abuse

5. **PowerShell Script Block Correlation** - PowerShell EID 4104 containing references to InstallUtil test framework functions combined with subsequent InstallUtil process creation

6. **Compiler Artifact Pattern** - Sysmon EID 11 showing creation of temporary directories with compiler output files (.cs, .cmdline, .tmp, .out, .err) indicating dynamic code compilation

7. **InstallUtil Parameter Anomalies** - Detection of InstallUtil executions with uncommon parameter combinations like "/installtype=notransaction" which are rarely used in legitimate installations
