# T1218.007-10: Msiexec — Msiexec.exe - Execute the DllUnregisterServer function of a DLL

## Technique Context

T1218.007 (Msiexec) is a defense evasion technique where attackers abuse the Windows Installer service (msiexec.exe) to proxy execution of malicious code. Msiexec is a signed Microsoft binary that can load and execute DLLs through various command-line switches, making it an attractive living-off-the-land binary (LOLBin) for bypassing application whitelisting and gaining trusted execution context. The detection community focuses on unusual msiexec command-line patterns, particularly the `/z` switch which calls DllUnregisterServer export functions in arbitrary DLLs, and child process spawning from msiexec that deviates from normal installer behavior.

## What This Dataset Contains

This dataset captures a complete execution chain showing msiexec.exe being used with the `/z` switch to load and execute a malicious DLL. The Security event log shows the full process creation chain: PowerShell (PID 37672) → cmd.exe with command `"cmd.exe" /c c:\windows\system32\msiexec.exe /z "C:\AtomicRedTeam\atomics\T1218.007\bin\MSIRunner.dll"` → msiexec.exe with command `c:\windows\system32\msiexec.exe  /z "C:\AtomicRedTeam\atomics\T1218.007\bin\MSIRunner.dll"` → PowerShell with command `powershell.exe -nop -Command Write-Host DllUnregisterServer export executed me; exit`. 

Sysmon captures detailed process creation events (EID 1) for all key processes including whoami.exe (system discovery), cmd.exe, msiexec.exe, and the spawned PowerShell instance. The PowerShell logging shows the malicious payload execution with a Write-Host command proving the DllUnregisterServer function was successfully called. Image load events (EID 7) document .NET runtime loading in the PowerShell processes and Windows Defender DLL loading indicating real-time protection was active.

## What This Dataset Does Not Contain

The dataset lacks direct evidence of the DLL loading by msiexec.exe itself - there are no Sysmon EID 7 (Image Loaded) events showing msiexec.exe loading the target MSIRunner.dll. This suggests the sysmon-modular config may not capture all image loads for msiexec.exe, or the DLL loading occurred through mechanisms not captured by standard image load monitoring. There are also no file access events showing msiexec.exe reading the target DLL file, and no registry modifications that might typically accompany DLL registration/unregistration activities.

## Assessment

This dataset provides excellent detection value for T1218.007 msiexec abuse. The Security audit logs capture the complete attack chain with full command lines, making it straightforward to detect the suspicious `/z` parameter usage and the unexpected PowerShell child process spawning from msiexec.exe. The combination of process creation telemetry from both Security and Sysmon channels provides redundant coverage and different levels of detail. While missing some lower-level DLL loading telemetry, the high-level process execution flow is comprehensively documented and represents the primary detection vectors security teams would rely on for this technique.

## Detection Opportunities Present in This Data

1. **Msiexec.exe with suspicious command-line parameters** - Security EID 4688 shows msiexec.exe launched with `/z` switch targeting a non-standard DLL path outside typical installer directories

2. **Unexpected child process from msiexec.exe** - Process creation events show PowerShell spawning from msiexec.exe, which deviates from normal Windows Installer behavior of only spawning installer-related processes

3. **Msiexec.exe loading DLLs from non-standard locations** - Command line references `C:\AtomicRedTeam\atomics\T1218.007\bin\MSIRunner.dll` rather than typical installer package locations

4. **Process ancestry chain analysis** - The full chain PowerShell → cmd.exe → msiexec.exe → PowerShell represents an unusual execution pattern for legitimate software installation

5. **Msiexec.exe with non-installer file extensions** - The target file has a `.dll` extension rather than expected `.msi`, `.msp`, or `.msu` installer formats

6. **Suspicious working directory for msiexec.exe** - Process executed from `C:\Windows\Temp\` rather than typical installer staging locations

7. **PowerShell execution with NOPROFILE flag from msiexec.exe parent** - The spawned PowerShell uses `-nop` parameter which is commonly associated with evasion techniques
