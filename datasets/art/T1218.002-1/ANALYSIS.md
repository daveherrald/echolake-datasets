# T1218.002-1: Control Panel — Control Panel Items

## Technique Context

T1218.002 (Control Panel) is a defense evasion technique where adversaries abuse control.exe or rundll32.exe to proxy execution of malicious code through Control Panel Items (.cpl files). This technique leverages trusted Windows binaries to execute arbitrary code, potentially bypassing application allowlisting and appearing benign to defenders. The technique is commonly used by malware families and red teams because .cpl files are essentially DLLs with a different extension that can contain executable code. Detection engineers typically focus on unusual .cpl file locations, suspicious rundll32.exe command lines involving Control_RunDLL, and process chains involving control.exe followed by rundll32.exe execution.

## What This Dataset Contains

This dataset captures a complete control panel item execution chain initiated by PowerShell. Security event 4688 shows the process creation sequence: `powershell.exe` → `cmd.exe /c control.exe "C:\AtomicRedTeam\atomics\T1218.002\bin\calc.cpl"` → `control.exe "C:\AtomicRedTeam\atomics\T1218.002\bin\calc.cpl"` → `rundll32.exe Shell32.dll,Control_RunDLL "C:\AtomicRedTeam\atomics\T1218.002\bin\calc.cpl"` → `rundll32.exe "C:\Windows\SysWOW64\shell32.dll",#44 "C:\AtomicRedTeam\atomics\T1218.002\bin\calc.cpl"` → `cmd.exe /c c:\windows\system32\calc.exe` → `calc.exe`.

Sysmon events provide additional detail: EID 1 (Process Create) captures the key LOLBin executions including rundll32.exe with rule names "technique_id=T1202" and "technique_id=T1218.011". EID 10 (Process Access) shows PowerShell accessing both whoami.exe and cmd.exe with full access rights (0x1FFFFF). EID 7 (Image Load) events capture urlmon.dll loading in control.exe, rundll32.exe processes, and calc.exe, indicating network capability preparation.

The PowerShell channel contains only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) with no technique-specific content. All processes execute under NT AUTHORITY\SYSTEM context and complete successfully with exit status 0x0.

## What This Dataset Does Not Contain

This dataset lacks file system telemetry showing the actual .cpl file access or modification. There are no network connection events despite urlmon.dll loading, suggesting the calc.cpl payload doesn't establish external communications. The dataset doesn't capture registry modifications that might occur during .cpl execution or any persistence mechanisms. Sysmon ProcessCreate filtering means some intermediate processes may not appear in EID 1 events, though Security 4688 provides complete process coverage. The test executes a benign calculator payload rather than demonstrating more complex .cpl capabilities like credential harvesting or lateral movement.

## Assessment

This dataset provides excellent coverage for T1218.002 detection development. The Security channel delivers complete process lineage with command lines, showing the classic control.exe → rundll32.exe execution pattern. Sysmon enriches this with process GUIDs, hashes, and parent-child relationships. The technique evidence is clear and unambiguous, making this dataset valuable for testing detection rules focused on control panel item abuse. The multi-stage execution chain (32-bit and 64-bit rundll32.exe) demonstrates Windows' automatic architecture handling. However, the benign payload limits insights into more sophisticated .cpl abuse scenarios.

## Detection Opportunities Present in This Data

1. **Process chain detection**: Alert on control.exe followed by rundll32.exe with Control_RunDLL parameter and suspicious .cpl file paths outside standard Windows directories

2. **Command line analysis**: Detect rundll32.exe executions with Shell32.dll,Control_RunDLL arguments pointing to non-standard .cpl locations

3. **Parent-child process relationships**: Monitor for cmd.exe or PowerShell spawning control.exe with .cpl file arguments

4. **File extension abuse**: Alert on .cpl files executed from non-system directories (e.g., user profiles, temp directories, external paths)

5. **Rundll32.exe ordinal usage**: Detect rundll32.exe using shell32.dll with ordinal #44 which corresponds to Control_RunDLL function

6. **Process access patterns**: Monitor PowerShell processes accessing child processes with full rights (0x1FFFFF) during control panel execution chains

7. **Architecture transitions**: Detect 64-bit rundll32.exe spawning 32-bit rundll32.exe, which may indicate control panel item execution

8. **Suspicious .cpl file locations**: Alert on control.exe or rundll32.exe accessing .cpl files from AtomicRedTeam, Downloads, or other non-standard directories
