# T1137.002-1: Office Test — Office Application Startup Test Persistence (HKCU)

## Technique Context

T1137.002 Office Test is a persistence mechanism that exploits Microsoft Office's support for test applications through the "Office Test" registry subkey. Attackers can register malicious DLLs under `HKEY_CURRENT_USER\Software\Microsoft\Office test\Special\Perf` or `HKEY_LOCAL_MACHINE` variants, which Office applications automatically load during startup. This technique provides a stealthy persistence method since the registry path appears benign and Office's DLL loading behavior is expected.

The detection community focuses on monitoring registry modifications to Office Test keys, unusual DLL loads from Office applications, and process creation patterns involving Office applications with suspicious command-line arguments. This technique is particularly concerning because it leverages legitimate Office functionality and can execute code with user-level permissions whenever Office applications start.

## What This Dataset Contains

This dataset captures a failed attempt to establish Office Test persistence. The PowerShell script in EID 4104 shows the technique logic: `reg add "HKEY_CURRENT_USER\Software\Microsoft\Office test\Special\Perf" /t REG_SZ /d "C:\AtomicRedTeam\atomics\T1137.002\bin\officetest_x64.dll" /f`. The script attempts to create a Word.Application COM object to determine Office architecture, but fails with PowerShell error EID 4100: "Retrieving the COM class factory for component with CLSID {00000000-0000-0000-0000-000000000000} failed due to the following error: 80040154 Class not registered".

Security EID 4688 events capture the PowerShell process creation with the full command line showing the persistence attempt. The process chain shows powershell.exe spawning whoami.exe (PID 26876) and another powershell.exe instance (PID 25712) that executes the Office Test script.

Sysmon captures process creation events for both whoami.exe (EID 1) and the child PowerShell process (EID 1) with complete command lines. Multiple Sysmon EID 7 events show .NET runtime DLL loads and Windows Defender components (MpOAV.dll, MpClient.dll) being loaded into PowerShell processes. Sysmon EID 10 events capture process access attempts between PowerShell processes. Sysmon EID 17 events show PowerShell named pipe creation for inter-process communication.

## What This Dataset Does Not Contain

The dataset lacks evidence of successful Office Test persistence since Microsoft Office is not installed on this test system. There are no registry modification events showing the actual creation of the Office Test key, which would typically appear as registry creation/modification events. No reg.exe process creation events appear despite the script invoking `reg add` commands.

The PowerShell error messages indicate the technique failed at the Office detection phase, so no actual persistence mechanism was established. Missing are any Office application process creation events (WINWORD.exe), DLL load events from Office processes, or registry writes to the Office Test keys that would indicate successful technique execution.

## Assessment

This dataset provides moderate value for detection engineering focused on Office Test persistence attempts rather than successful implementations. The PowerShell script block logging (EID 4104) captures the complete technique implementation including registry paths and DLL references, making it excellent for content-based detection rules.

The Security 4688 events with command-line logging provide another detection avenue for monitoring PowerShell execution of Office Test scripts. However, the dataset's utility is limited for understanding successful Office Test persistence behavior since the technique fails before registry modification occurs.

The data quality is high for attempt-based detections but insufficient for understanding the complete attack lifecycle including DLL loading from Office applications.

## Detection Opportunities Present in This Data

1. **PowerShell script block detection** - Monitor EID 4104 for scripts containing "HKEY_CURRENT_USER\Software\Microsoft\Office test\Special\Perf" registry paths and "reg add" commands targeting Office Test keys.

2. **Command-line analysis for Office Test patterns** - Detect Security EID 4688 process creation events where CommandLine contains both "Office test" and registry modification syntax.

3. **PowerShell COM object creation failures** - Alert on PowerShell EID 4100 errors mentioning "Word.Application" COM object failures, which may indicate Office Test reconnaissance attempts on systems without Office.

4. **Process creation correlation** - Monitor for PowerShell processes spawning child PowerShell processes with command lines referencing AtomicRedTeam paths and Office-related content.

5. **Registry path monitoring** - Implement detection for any process attempting to access or modify registry paths containing "Software\Microsoft\Office test" regardless of success.

6. **Script content analysis** - Develop YARA rules or string matching for PowerShell content containing combinations of "Word.Application", "Office test", and "Perf" registry subkeys.
