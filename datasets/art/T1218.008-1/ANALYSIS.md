# T1218.008-1: Odbcconf — Odbcconf.exe - Execute Arbitrary DLL

## Technique Context

T1218.008 (Odbcconf) is a defense evasion technique where attackers abuse the legitimate Windows ODBC configuration utility (odbcconf.exe) to proxy execution of malicious DLLs. This signed Microsoft binary can load arbitrary DLLs through the REGSVR action, allowing attackers to execute code while appearing to use a trusted system utility. The detection community focuses on monitoring odbcconf.exe command lines containing REGSVR actions, especially those pointing to suspicious file paths, non-standard DLL locations, or DLLs with unusual characteristics.

## What This Dataset Contains

This dataset captures a successful execution of the Atomic Red Team T1218.008-1 test, which uses odbcconf.exe to load a test DLL. The key evidence appears in the process creation chain:

- **Sysmon EID 1**: PowerShell launches cmd.exe with command line `"cmd.exe" /c odbcconf.exe /S /A {REGSVR "C:\AtomicRedTeam\atomics\T1218.008\src\Win32\T1218-2.dll"}`
- **Sysmon EID 1**: cmd.exe spawns odbcconf.exe with command line `odbcconf.exe /S /A {REGSVR "C:\AtomicRedTeam\atomics\T1218.008\src\Win32\T1218-2.dll"}`
- **Security EID 4688**: Corresponding process creation events with full command lines showing the REGSVR action targeting the test DLL

The dataset shows the process exits with error codes (Security EID 4689 shows odbcconf.exe exiting with status 0xFFFFFFF6), indicating the DLL loading likely failed, but the telemetry still captures the attempt. Process access events (Sysmon EID 10) show PowerShell accessing both the spawned cmd.exe and odbcconf.exe processes with full access rights.

## What This Dataset Does Not Contain

The dataset lacks evidence of successful DLL execution aftermath. There are no image load events showing the target DLL being loaded, no network connections, registry modifications, or file operations that would typically follow successful malicious DLL execution. The error exit codes suggest the test DLL may not have loaded properly, which explains the absence of post-execution artifacts. Additionally, there are no Windows Defender alert events, suggesting the test DLL was not flagged as malicious.

## Assessment

This dataset provides excellent telemetry for detecting odbcconf.exe abuse attempts. The Sysmon ProcessCreate events with include-mode filtering successfully captured the suspicious odbcconf.exe execution, and Security 4688 events provide complete command-line coverage. The process chain is clearly visible, and the specific REGSVR syntax targeting an unusual file path creates strong detection opportunities. While the technique may not have fully succeeded, the attempt telemetry is comprehensive and realistic for detection engineering purposes.

## Detection Opportunities Present in This Data

1. **Odbcconf REGSVR Action**: Monitor Sysmon EID 1 and Security EID 4688 for odbcconf.exe processes with command lines containing "REGSVR" followed by file paths outside standard Windows directories

2. **Suspicious DLL Paths**: Alert on odbcconf.exe loading DLLs from non-standard locations like user directories, temp folders, or paths containing "Atomic" or test-related keywords

3. **Process Chain Analysis**: Detect odbcconf.exe spawned by cmd.exe or PowerShell, especially when the parent process was not launched interactively

4. **Command Line Patterns**: Create signatures for odbcconf.exe command lines using the /S (silent) and /A (action) flags in combination with REGSVR syntax

5. **Unsigned DLL Loading**: Correlate odbcconf.exe execution with subsequent image load events for unsigned or suspicious DLLs (though this specific execution didn't generate such events)

6. **Process Access Monitoring**: Use Sysmon EID 10 events showing PowerShell or other scripting engines accessing odbcconf.exe processes with high privilege levels as a supplementary indicator
