# T1106-2: Native API — WinPwn - Get SYSTEM shell - Pop System Shell using CreateProcess technique

## Technique Context

T1106 (Native API) encompasses adversary use of Windows native APIs to execute malicious functionality. This particular test implements a parent process ID (PPID) spoofing technique through the CreateProcess Windows API, using extended startup information structures to make a new PowerShell process appear to have been spawned by LSASS instead of the actual parent. This is a common post-exploitation technique for evading process tree-based detection and achieving SYSTEM-level privileges while masquerading as a legitimate system process.

The technique downloads a C# implementation of PPID spoofing from GitHub, compiles it in-memory using Add-Type, and then uses the CreateProcess API with STARTUPINFOEX and PROC_THREAD_ATTRIBUTE_PARENT_PROCESS to spawn a PowerShell shell with LSASS as the fake parent. Detection engineers focus on identifying unusual parent-child relationships, in-memory compilation activities, and direct Windows API usage patterns.

## What This Dataset Contains

This dataset captures a successful PPID spoofing execution with rich telemetry across multiple phases:

**Process execution chain**: Security 4688 events show the complete process genealogy: initial PowerShell (PID 17752) → child PowerShell with download command (PID 15304) → C# compiler csc.exe (PID 17280) → cvtres.exe (PID 18700) → final spoofed PowerShell (PID 18152) with `ParentProcessId: 780` (lsass.exe).

**Script download and compilation**: PowerShell 4104 events contain the complete C# source code for the PPID spoofing technique, showing `Add-Type -TypeDefinition` with DLL imports for `CreateProcess`, `UpdateProcThreadAttribute`, and `InitializeProcThreadAttributeList`. The script block contains the full `HighPrivs.SystemPPID` class implementation.

**File system artifacts**: Sysmon 11 events show temporary file creation in `C:\Windows\SystemTemp\zeeymo5n\` including the C# source file, compilation artifacts, and resource files created during the Add-Type compilation process.

**Network activity**: Sysmon 22 DNS query for `raw.githubusercontent.com` and associated IP resolution, demonstrating the external script download.

**Process access patterns**: Multiple Sysmon 10 events show PowerShell accessing LSASS (PID 780) with `GrantedAccess: 0x1F3FFF`, which is consistent with the PPID spoofing technique querying process information and handles.

**Critical evidence**: Security 4688 shows the final spoofed process with `Creator Process ID: 0x30c` (LSASS) and `Creator Process Name: C:\Windows\System32\lsass.exe`, proving the PPID spoofing succeeded.

## What This Dataset Does Not Contain

The dataset lacks network connection telemetry for the actual GitHub download - Sysmon 3 events only show Windows Defender connections, suggesting the PowerShell WebClient download may have completed before Sysmon network monitoring fully initialized or was filtered out by the configuration.

Sysmon 1 ProcessCreate events are missing for some processes in the chain due to the include-mode filtering configuration that only captures processes matching known-suspicious patterns. The parent PowerShell processes are captured due to LOLBin detection rules.

No registry modifications are present, which is expected since this technique operates entirely through API calls and in-memory compilation without persistent registry changes.

The dataset doesn't contain any Windows Defender blocking events or AMSI detections, indicating the technique successfully evaded endpoint protection during execution.

## Assessment

This dataset provides excellent coverage for detecting PPID spoofing techniques through multiple complementary data sources. The Security event logs clearly demonstrate the anomalous parent-child relationship that would trigger most PPID spoofing detections. The PowerShell script block logging captures the complete attack code including API signatures and technique implementation. Sysmon process access events show the characteristic LSASS access patterns associated with this technique.

The combination of process creation telemetry, PowerShell logging, file creation events, and process access monitoring creates multiple detection opportunities. The temporal correlation between these events provides strong evidence of coordinated malicious activity rather than legitimate system operations.

## Detection Opportunities Present in This Data

1. **Anomalous parent-child process relationships** - Security 4688 showing PowerShell spawned by lsass.exe (Creator Process Name: C:\Windows\System32\lsass.exe) when LSASS typically doesn't spawn interactive processes

2. **In-memory C# compilation patterns** - PowerShell 4104 script blocks containing Add-Type with DLL imports for CreateProcess, UpdateProcThreadAttribute, and other process manipulation APIs

3. **LSASS process access from PowerShell** - Sysmon 10 events showing PowerShell accessing lsass.exe with high privileges (GrantedAccess: 0x1F3FFF) outside of normal system operations

4. **Remote script download and execution** - PowerShell command lines containing downloadstring() methods combined with DNS queries to raw.githubusercontent.com

5. **Temporary file creation in system directories** - Sysmon 11 events showing compilation artifacts in C:\Windows\SystemTemp\ with random directory names during Add-Type operations

6. **Process spawning with EXTENDED_STARTUPINFO_PRESENT flag** - Code analysis of PowerShell script blocks showing CreateProcessFlags.EXTENDED_STARTUPINFO_PRESENT usage

7. **Compiler process chains from PowerShell** - Process creation of csc.exe and cvtres.exe as children of PowerShell processes, indicating dynamic compilation activity

8. **PowerShell execution policy bypass** - PowerShell 4103 showing Set-ExecutionPolicy with Bypass parameter in SYSTEM context

9. **Named pipe creation patterns** - Sysmon 17 showing PSHost pipes created by processes with suspicious parent relationships
