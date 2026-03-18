# T1218.011-12: Rundll32 — Rundll32 with Control_RunDLL

## Technique Context

T1218.011 (Rundll32) is a defense evasion technique where attackers abuse the legitimate Windows rundll32.exe utility to execute malicious code. Rundll32 is designed to run DLL functions from the command line, making it a powerful proxy execution method. The Control_RunDLL export from shell32.dll is particularly interesting because it's the standard mechanism for launching Control Panel applets, but can be abused to execute arbitrary DLLs that implement the required entry point. This technique allows attackers to execute code while appearing to use a legitimate Windows binary, potentially bypassing application whitelisting and other endpoint protections. Detection engineers focus on command line patterns, parent-child relationships, and unusual DLL loads through rundll32.

## What This Dataset Contains

This dataset captures a successful execution of rundll32 with Control_RunDLL loading a malicious calc.dll. The complete process chain is visible in Security event logs:

1. **PowerShell test framework**: Security 4688 shows `powershell.exe` as the execution framework
2. **Command shell**: Security 4688 captures `"cmd.exe" /c rundll32.exe shell32.dll,Control_RunDLL "C:\AtomicRedTeam\atomics\T1047\bin\calc.dll"`
3. **Rundll32 execution**: Security 4688 shows `rundll32.exe shell32.dll,Control_RunDLL "C:\AtomicRedTeam\atomics\T1047\bin\calc.dll"`
4. **Payload execution**: Security 4688 captures `calc` (the Windows Calculator launched by the malicious DLL)

Sysmon provides additional context with ProcessCreate events (EID 1) for cmd.exe, rundll32.exe, and the spawned calc.exe process, including full command lines and process GUIDs. Process access events (EID 10) show PowerShell accessing both whoami.exe and cmd.exe with full access rights (0x1FFFFF). The technique successfully executed without any exit code indicating Defender intervention — all processes show normal exit status 0x0.

## What This Dataset Does Not Contain

The dataset lacks file creation or modification events for the malicious calc.dll itself, suggesting either the DLL was pre-staged or Sysmon's file monitoring didn't capture its creation. Network activity that might result from a more sophisticated payload is absent. Registry modifications that some rundll32 abuse techniques might generate are not present. The PowerShell channel contains only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) rather than the actual technique execution commands.

## Assessment

This dataset provides excellent telemetry for rundll32 defense evasion detection. The Security channel's 4688 events with command-line logging capture the complete attack flow with high fidelity. Sysmon's ProcessCreate events add valuable process relationship context and file hashes. The combination of these data sources enables detection of the specific Control_RunDLL pattern, suspicious parent-child relationships (cmd.exe → rundll32.exe → calc.exe), and unusual DLL paths. The successful execution without defensive intervention demonstrates how this technique can evade real-time protection, making the telemetry representative of actual attack scenarios.

## Detection Opportunities Present in This Data

1. **Rundll32 with Control_RunDLL and non-standard DLL paths** - Security 4688 and Sysmon EID 1 show rundll32.exe executing shell32.dll,Control_RunDLL with a DLL outside standard system locations (`C:\AtomicRedTeam\atomics\T1047\bin\calc.dll`)

2. **Suspicious rundll32 parent process relationships** - Process chain shows cmd.exe spawning rundll32.exe, which could indicate scripted or automated execution rather than user-initiated Control Panel access

3. **Rundll32 spawning unexpected child processes** - The calc.exe process creation by rundll32.exe is anomalous, as legitimate Control Panel applets typically don't spawn additional executables

4. **PowerShell process access to cmd.exe** - Sysmon EID 10 shows PowerShell accessing cmd.exe with full rights (0x1FFFFF), potentially indicating process injection or manipulation

5. **Command line patterns for Control_RunDLL abuse** - The specific syntax `rundll32.exe shell32.dll,Control_RunDLL` with a non-CPL file extension (.dll instead of .cpl) indicates potential abuse

6. **File path analysis for suspicious DLL locations** - The DLL path contains "AtomicRedTeam" and is located in a non-standard directory, which could be detected through path analysis rules
