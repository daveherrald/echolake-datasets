# T1055-6: Process Injection — Process Injection with Go using UuidFromStringA WinAPI

## Technique Context

Process injection is a fundamental technique used by attackers to execute arbitrary code within the address space of a legitimate process. This specific test implements a Go-based process injection technique utilizing the Windows UuidFromStringA API, which can be abused to allocate and execute shellcode by converting UUID strings into binary data that represents executable code. The detection community focuses on monitoring cross-process operations, unusual API usage patterns, and process access events that indicate potential code injection activities. This technique is particularly interesting because it leverages a seemingly benign UUID conversion function for malicious code execution, making it a creative evasion method.

## What This Dataset Contains

The dataset captures a PowerShell-based execution chain where the UuidFromStringA.exe binary is launched with the `-debug` flag. The Security events show process creation with command line `"powershell.exe" & {C:\AtomicRedTeam\atomics\T1055\bin\x64\UuidFromStringA.exe -debug}` (EID 4688). However, the expected UuidFromStringA.exe process creation is notably absent from both Sysmon and Security logs, indicating the binary either failed to start or was blocked.

Sysmon captures extensive process access telemetry showing PowerShell accessing both whoami.exe (PID 7656) and another PowerShell instance (PID 44896) with full access rights (0x1FFFFF) through EID 10 events. The call traces reveal these operations originating from System.Management.Automation.ni.dll, indicating PowerShell's process manipulation capabilities.

The dataset includes comprehensive DLL loading events (EID 7) showing .NET Framework components (mscoree.dll, mscoreei.dll, clr.dll, clrjit.dll) and Windows Defender modules (MpOAV.dll, MpClient.dll) being loaded into multiple PowerShell processes. PowerShell script block logging (EID 4104) captures the test execution command but consists primarily of framework boilerplate with minimal technique-specific content.

Process termination events (EID 4689) show clean exit codes (0x0) for all processes involved.

## What This Dataset Does Not Contain

Critically, this dataset lacks the actual UuidFromStringA.exe process execution despite the command being issued. The Sysmon ProcessCreate events (EID 1) show whoami.exe and PowerShell processes but no evidence of the target injection binary. This suggests Windows Defender or another security control likely blocked the execution before the process could start, or the binary encountered a runtime error.

The dataset contains no network connections, registry modifications, or file creation events related to the injection technique itself. There are no memory allocation or thread creation events that would typically accompany successful process injection. The PowerShell script blocks don't contain any UUID strings or injection-related code, only execution policy changes and error handling boilerplate.

## Assessment

This dataset provides limited utility for understanding successful process injection techniques using UuidFromStringA. While it demonstrates the execution attempt and PowerShell's cross-process access capabilities, the absence of the actual injection binary execution significantly reduces its value for detection engineering. The Sysmon EID 10 events showing process access are valuable for detecting injection attempts, but without the corresponding injection payload execution, the dataset is more useful for understanding blocked attack attempts than successful ones.

The comprehensive DLL loading telemetry and process access events do provide good examples of legitimate PowerShell behavior that could serve as baseline data for behavioral analysis.

## Detection Opportunities Present in This Data

1. **Cross-Process Access Detection**: Monitor Sysmon EID 10 events where PowerShell processes access other processes with high privilege levels (0x1FFFFF), especially when combined with System.Management.Automation call traces.

2. **Suspicious PowerShell Command Lines**: Alert on Security EID 4688 events containing references to AtomicRedTeam paths or unknown executables with debug parameters launched via PowerShell.

3. **Process Access Anomalies**: Detect when PowerShell accesses processes it doesn't typically interact with (like whoami.exe) using OpenProcess calls from .NET automation assemblies.

4. **Failed Process Execution Patterns**: Correlate PowerShell command execution with missing expected child processes to identify potential security control interventions.

5. **Multiple PowerShell Instance Spawning**: Monitor for rapid creation of multiple PowerShell processes in short timeframes, which may indicate injection framework activity.

6. **Defender DLL Loading Correlation**: Track when both MpOAV.dll and MpClient.dll load into processes simultaneously, potentially indicating active security scanning during suspicious activities.
