# T1218.010-3: Regsvr32 — Regsvr32 local DLL execution

## Technique Context

T1218.010 (Regsvr32) is a defense evasion technique where attackers abuse the legitimate Windows regsvr32.exe utility to proxy execution of malicious code. Regsvr32 is designed to register and unregister COM DLLs and ActiveX controls, but attackers leverage it to execute arbitrary code while appearing to use a trusted, signed Microsoft binary. This technique is particularly valuable because regsvr32.exe is commonly whitelisted by application control solutions and may be overlooked by security monitoring focused on traditional executables.

Attackers typically use regsvr32 in two main ways: executing local malicious DLLs (as demonstrated in this test) or fetching and executing remote scripts via the `/u` and `/i` flags with URLs. The detection community focuses on monitoring regsvr32 command lines for suspicious arguments, unusual file paths, network connections from regsvr32 processes, and DLL loads from unexpected locations. Process creation events, command-line analysis, and file system monitoring are the primary detection vectors.

## What This Dataset Contains

This dataset captures a successful local DLL execution using regsvr32.exe. The attack chain begins with PowerShell execution and proceeds through these key events:

The command executed was: `"cmd.exe" /c IF "%PROCESSOR_ARCHITECTURE%"=="AMD64" (C:\Windows\syswow64\regsvr32.exe /s C:\AtomicRedTeam\atomics\T1218.010\bin\AllTheThingsx86.dll) ELSE ( C:\Windows\system32\regsvr32.exe /s C:\AtomicRedTeam\atomics\T1218.010\bin\AllTheThingsx86.dll )`

Security Event ID 4688 shows the full process chain: PowerShell (PID 6292) → cmd.exe (PID 38904) → regsvr32.exe (PID 16736). The regsvr32 process was created with the command line `C:\Windows\syswow64\regsvr32.exe /s C:\AtomicRedTeam\atomics\T1218.010\bin\AllTheThingsx86.dll`.

Sysmon Event ID 1 captures the regsvr32 process creation with full details including the target DLL path `C:\AtomicRedTeam\atomics\T1218.010\bin\AllTheThingsx86.dll` and the `/s` flag for silent execution. Notably, the regsvr32 process exited with status 0x3, indicating an error condition rather than successful execution.

The dataset shows typical PowerShell initialization events and .NET runtime loading through Sysmon Event ID 7, along with Windows Defender DLL loads indicating active endpoint protection monitoring.

## What This Dataset Does Not Contain

The dataset lacks evidence of successful DLL registration or execution of malicious code within the target DLL. The regsvr32 process exit code 0x3 suggests the operation failed, likely due to the test DLL not implementing proper COM interfaces or Windows Defender intervention. 

There are no network connection events (Sysmon Event ID 3) showing potential C2 communication, no additional suspicious file system activity beyond the initial execution attempt, and no registry modifications that would typically accompany successful COM DLL registration. The absence of Event ID 7 (Image Load) events for the target DLL confirms it was not successfully loaded into the regsvr32 process.

Sysmon ProcessCreate events are missing for some expected child processes due to the sysmon-modular configuration's include-mode filtering, though Security 4688 events provide comprehensive process creation coverage. The PowerShell events contain only test framework boilerplate rather than the actual technique execution commands.

## Assessment

This dataset provides excellent telemetry for detecting regsvr32 abuse attempts, even when the technique fails to execute successfully. The Security 4688 events capture the complete command line including the suspicious DLL path and silent execution flag, while Sysmon adds valuable process tree context and file hashes. The exit code 0x3 demonstrates how endpoint protection or improper DLL structure can prevent successful execution while still generating detectable artifacts.

The command-line patterns in this dataset are highly distinctive for detection engineering: the conditional architecture check, use of the `/s` flag for silent operation, and execution of a DLL from a non-standard path (AtomicRedTeam directory). These elements make this dataset particularly valuable for building robust detection rules that can identify regsvr32 abuse regardless of execution success.

## Detection Opportunities Present in This Data

1. **Regsvr32 execution with non-standard DLL paths** - Monitor Security 4688 and Sysmon 1 for regsvr32.exe command lines containing DLL paths outside of System32, SysWOW64, or Program Files directories.

2. **Regsvr32 silent execution flag usage** - Alert on regsvr32.exe processes using the `/s` flag, which is commonly used by attackers to suppress error dialogs and avoid user interaction.

3. **Regsvr32 spawned from scripting engines** - Detect regsvr32.exe processes with PowerShell, cmd.exe, or other scripting interpreters as parent processes, indicating potential automated execution.

4. **Suspicious regsvr32 process exit codes** - Monitor for regsvr32 processes exiting with non-zero status codes (like 0x3 in this case), which may indicate failed malicious execution attempts.

5. **Regsvr32 execution from temporary or user-writable directories** - Flag regsvr32.exe processes accessing DLLs from TEMP, user profile directories, or other writable locations where attackers commonly stage payloads.

6. **Process chain analysis for regsvr32** - Build detections that examine the full process ancestry when regsvr32 executes, particularly looking for origination from Office applications, browsers, or other initial access vectors.

7. **Conditional architecture checking patterns** - Detect command lines containing processor architecture environment variable checks followed by regsvr32 execution, as this pattern is common in automated attack frameworks.
