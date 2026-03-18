# T1218.010-5: Regsvr32 — Regsvr32 Silent DLL Install Call DllRegisterServer

## Technique Context

T1218.010 (Regsvr32) is a defense evasion technique where attackers abuse the legitimate Microsoft utility regsvr32.exe to proxy execution of malicious code. This technique allows attackers to execute arbitrary code while appearing to use a trusted, signed Windows binary. The detection community focuses on unusual command-line patterns, especially the `/s` (silent) and `/i` (install) flags, network connections from regsvr32.exe, and execution of DLLs from suspicious locations. This specific test demonstrates the "silent install" variant, where regsvr32 calls the DllRegisterServer export function of a DLL without displaying dialog boxes, making it particularly useful for stealthy execution.

## What This Dataset Contains

The dataset captures a complete regsvr32.exe execution chain initiated by PowerShell. The Security channel shows the full process creation sequence: PowerShell (PID 6744) spawns cmd.exe with command line `"cmd.exe" /c C:\Windows\system32\regsvr32.exe /s /i "C:\AtomicRedTeam\atomics\T1218.010\bin\AllTheThingsx86.dll"`, which then creates regsvr32.exe (PID 44836) with command line `C:\Windows\system32\regsvr32.exe /s /i "C:\AtomicRedTeam\atomics\T1218.010\bin\AllTheThingsx86.dll"`. The regsvr32.exe process exits with status `0x3`, indicating an error condition.

Sysmon captures the regsvr32.exe process creation (EID 1) with rule name `technique_id=T1218.010,technique_name=Regsvr32`, showing the process was correctly identified by the sysmon-modular configuration. The dataset includes process access events (EID 10) showing PowerShell accessing both the whoami.exe and cmd.exe child processes with full access rights (0x1FFFFF), and multiple image load events (EID 7) documenting the .NET runtime initialization in PowerShell.

## What This Dataset Does Not Contain

The dataset lacks several critical elements for complete T1218.010 analysis. There are no registry modifications (Sysmon EID 13) that would typically occur during DLL registration, suggesting the DLL registration may have failed. No file creation events show the target DLL being written or accessed, and there are no network connections from regsvr32.exe itself, which are common indicators of malicious regsvr32 usage. The PowerShell script block logging contains only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) rather than the actual test execution commands. Most importantly, the regsvr32 process exit status of `0x3` indicates the technique execution failed, likely due to Windows Defender interference or DLL compatibility issues, so this dataset represents an unsuccessful attempt rather than a successful technique execution.

## Assessment

This dataset provides limited utility for detection engineering due to the failed execution, but offers valuable insights into regsvr32 attempt detection. The Security 4688 events with command-line logging provide the most reliable detection data source, clearly showing the regsvr32 invocation with `/s /i` flags and a DLL path outside system directories. The Sysmon process creation events add additional context with file hashes and parent process relationships. However, the lack of successful technique artifacts (registry changes, file operations, network activity) means this data is more useful for building detections around regsvr32 process creation patterns than for understanding the full attack lifecycle. The error exit status actually provides a useful data point for distinguishing between successful and failed attempts.

## Detection Opportunities Present in This Data

1. **Regsvr32 Process Creation with Suspicious Flags**: Monitor Security EID 4688 for regsvr32.exe with command lines containing `/s` (silent) and `/i` (install) flags, especially when targeting DLLs outside Windows system directories.

2. **Regsvr32 Spawned by Scripting Engines**: Detect regsvr32.exe with parent processes of powershell.exe, cmd.exe, wscript.exe, or cscript.exe using Sysmon EID 1 ParentImage field.

3. **Regsvr32 DLL Loading from Non-Standard Paths**: Alert on regsvr32.exe targeting DLLs in user-writable directories like `C:\AtomicRedTeam\`, temp directories, or user profiles.

4. **Command Shell Proxy Execution**: Monitor for cmd.exe executing regsvr32.exe via `/c` flag, indicating potential script-based proxy execution.

5. **Process Access Patterns**: Track Sysmon EID 10 showing PowerShell or other script interpreters accessing regsvr32.exe child processes with high privilege access (0x1FFFFF).

6. **Failed Regsvr32 Execution**: Monitor Security EID 4689 for regsvr32.exe exits with non-zero status codes, which may indicate blocked malicious attempts or environment issues.

7. **PowerShell Execution Policy Bypass**: Correlate PowerShell EID 4103 showing Set-ExecutionPolicy Bypass with subsequent regsvr32.exe execution as part of attack chain analysis.
