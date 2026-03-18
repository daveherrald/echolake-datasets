# T1218.010-4: Regsvr32 — Regsvr32 Registering Non DLL

## Technique Context

T1218.010 (Regsvr32) is a defense evasion technique where attackers abuse the legitimate Windows regsvr32.exe utility to proxy execution of malicious code. Regsvr32 is designed to register and unregister DLLs in the Windows registry, but attackers exploit it to execute scripts or non-DLL files by leveraging COM object functionality or misusing its file handling capabilities.

This specific test variant attempts to register a non-DLL file (shell32.jpg) using regsvr32, which demonstrates how attackers might try to abuse the utility with unexpected file types. The detection community focuses on monitoring regsvr32 executions with unusual file extensions, network connections, child processes, and command-line patterns that deviate from normal administrative usage.

## What This Dataset Contains

The dataset captures a PowerShell-initiated execution chain where regsvr32 attempts to register a non-DLL file:

**Process Chain**: PowerShell → cmd.exe → regsvr32.exe
- Security 4688: `"cmd.exe" /c C:\Windows\system32\regsvr32.exe /s %temp%\shell32.jpg`
- Security 4688: `C:\Windows\system32\regsvr32.exe  /s C:\Windows\TEMP\shell32.jpg`
- Sysmon EID 1: Process creation events for whoami.exe, cmd.exe, and regsvr32.exe with full command lines

**Key Evidence**:
- Regsvr32 targeting non-DLL file: `C:\Windows\TEMP\shell32.jpg`
- Silent execution flag `/s` to suppress error dialogs
- Regsvr32 exit status 0x3 (Security 4689) indicating failure
- Process access events (Sysmon EID 10) showing PowerShell accessing child processes

**Sysmon Coverage**: Rich telemetry including process creation (EID 1), process access (EID 10), image loads (EID 7), and file creation (EID 11) events providing comprehensive visibility into the execution chain.

## What This Dataset Does Not Contain

The dataset lacks certain elements due to the failed execution and system configuration:

- **No network connections**: Regsvr32 failed before establishing any network communications (no Sysmon EID 3 events)
- **No DLL registration artifacts**: Since the technique failed with a non-DLL file, no actual COM registration occurred
- **Limited file system activity**: The target file `shell32.jpg` creation/modification events aren't captured, suggesting it may not have existed
- **No PowerShell script content**: PowerShell events only contain test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass)
- **Missing parent PowerShell process creation**: The parent PowerShell process creation isn't captured by Sysmon, likely due to the include-mode filtering

## Assessment

This dataset provides excellent visibility into a failed regsvr32 abuse attempt. The Security event channel captures the complete command-line arguments and process relationships, while Sysmon adds valuable process access telemetry. The failure scenario (exit code 0x3) is actually beneficial for detection development as it demonstrates both the attempt and the system's rejection of invalid input.

The combination of Security 4688 events with command-line logging and Sysmon process creation events provides redundant coverage, ensuring detection opportunities aren't missed. The process access events add depth for behavioral analysis, showing PowerShell's interaction with spawned processes.

## Detection Opportunities Present in This Data

1. **Regsvr32 with non-DLL file extensions** - Monitor regsvr32.exe command lines containing files without .dll, .ocx, or .ax extensions (Security 4688, Sysmon EID 1)

2. **Regsvr32 targeting temp directories** - Detect regsvr32 operations against files in %temp%, %tmp%, or other temporary locations (Security 4688 command line analysis)

3. **Silent regsvr32 execution** - Alert on regsvr32.exe with `/s` flag, especially when combined with unusual file types or locations

4. **Process chain analysis** - Monitor PowerShell → cmd.exe → regsvr32.exe execution chains as potential proxy execution attempts

5. **Regsvr32 exit code failures** - Correlate Security 4689 exit status codes (like 0x3) with preceding regsvr32 attempts to identify failed abuse attempts

6. **Cross-process access patterns** - Use Sysmon EID 10 to detect PowerShell processes accessing regsvr32 or cmd.exe with high privileges (0x1FFFFF access rights)

7. **Parent-child process relationships** - Alert when regsvr32.exe is spawned by cmd.exe which was spawned by PowerShell, indicating potential scripted abuse
