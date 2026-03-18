# T1218.004-8: InstallUtil — InstallUtil evasive invocation

## Technique Context

T1218.004 (InstallUtil) is a defense evasion technique where attackers abuse Microsoft's InstallUtil.exe utility to execute arbitrary code while bypassing application control mechanisms. InstallUtil.exe is a legitimate .NET Framework utility designed to install and uninstall server resources by executing the installer components in specified assemblies. Attackers exploit this by creating malicious installer assemblies that execute code in their constructors or overridden methods, effectively using a trusted, signed Microsoft binary as a proxy for code execution.

The detection community focuses on monitoring InstallUtil.exe executions, especially those targeting non-standard file extensions, assemblies in unusual locations, or InstallUtil copies in non-standard paths. This specific test (T1218.004-8) demonstrates an "evasive invocation" where InstallUtil.exe is copied to an alternate location (`C:\Windows\System32\Tasks\notepad.exe`) to potentially evade detection rules that only monitor the original InstallUtil.exe path.

## What This Dataset Contains

This dataset captures a complete evasive InstallUtil execution sequence with rich telemetry:

**Process Chain**: The execution begins with PowerShell loading the InstallUtil test framework, then copying `InstallUtil.exe` to `C:\Windows\System32\Tasks\notepad.exe`. Security event 4688 shows the renamed InstallUtil executing with command line `"C:\Windows\System32\Tasks\notepad.exe" readme.txt`.

**Assembly Compilation**: The test framework compiles a malicious installer assembly on-the-fly using csc.exe. Security events 4688 capture two csc.exe executions with command lines like `"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /noconfig /fullpaths @"C:\Windows\SystemTemp\zzkeupfp\zzkeupfp.cmdline"`. Sysmon event 1 captures these as well with rule matches for T1127 (Trusted Developer Utilities Proxy Execution).

**File Operations**: Sysmon event 11 captures the creation of `C:\Windows\System32\Tasks\notepad.exe` (the copied InstallUtil) and `C:\Windows\System32\Tasks\readme.txt` (the malicious assembly). Sysmon event 29 detects both as executable files with their full hash values.

**InstallUtil Execution**: Sysmon event 1 captures the renamed InstallUtil execution with rule match for T1218.004. The process loads .NET runtime components (events 7) and creates installer log files `readme.InstallLog` and `readme.InstallState` (events 11).

**PowerShell Evidence**: PowerShell script block logging (event 4104) captures the complete test script including the copying of InstallUtil and assembly compilation logic.

## What This Dataset Does Not Contain

**Network Activity**: No network connections are generated during this local assembly compilation and execution, so no Sysmon event 3 data is present.

**Registry Modifications**: The installer assembly used is minimal and doesn't perform registry operations, so no registry-related events appear.

**Original InstallUtil Path**: Since this test specifically uses path evasion, there are no events showing execution from the standard `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe` path.

**Defender Interference**: All processes exit with status 0x0, indicating successful execution without Windows Defender blocking the technique.

## Assessment

This dataset provides excellent coverage for detecting InstallUtil path evasion techniques. The combination of Security event 4688 (with command-line logging), Sysmon events 1, 11, and 29, plus PowerShell script block logging creates multiple detection opportunities. The data quality is high with complete process chains, file hashes, and command-line arguments captured. The presence of both the file copy operation and the subsequent execution provides detection engineers with multiple points in the attack chain to build rules against.

For InstallUtil detection specifically, this dataset is particularly valuable because it demonstrates how attackers might evade path-based detection rules, making it essential for testing detection logic that relies solely on process image paths rather than file signatures or command-line patterns.

## Detection Opportunities Present in This Data

1. **Renamed InstallUtil Detection**: Monitor for processes with InstallUtil.exe's file signature (SHA256: 4F02DE543316367945FDFB89DAFEB3A50E6C1E54DF015AD1732C15962206B647) executing from non-standard paths like `C:\Windows\System32\Tasks\notepad.exe`.

2. **File Copy to Suspicious Locations**: Alert on PowerShell copying files from .NET Framework directories to unusual locations, particularly when the source file is InstallUtil.exe.

3. **Assembly Compilation Patterns**: Detect csc.exe executions that compile assemblies to non-standard locations like `C:\Windows\System32\Tasks\` followed by InstallUtil-like executions.

4. **Suspicious File Extensions**: Monitor InstallUtil executions targeting files with non-standard extensions like `.txt` instead of typical `.dll` or `.exe` extensions.

5. **Installation State Files**: Watch for creation of `.InstallLog` and `.InstallState` files in unusual directories as indicators of InstallUtil activity.

6. **PowerShell Script Content**: Detect PowerShell scripts containing `Copy-Item` operations involving InstallUtil.exe combined with `System.Runtime.InteropServices.RuntimeEnvironment` calls.

7. **Process Access Patterns**: Monitor for PowerShell processes accessing newly created processes with full access rights (0x1FFFFF) as captured in the Sysmon event 10 data.

8. **Executable File Creation in System Paths**: Alert on creation of executable files in `C:\Windows\System32\Tasks\` or similar system directories by non-system processes.
