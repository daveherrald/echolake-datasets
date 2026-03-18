# T1055.001-1: Dynamic-link Library Injection — Process Injection via mavinject.exe

## Technique Context

T1055.001 (Dynamic-link Library Injection) is a process injection technique where adversaries force a running process to load and execute a malicious DLL. This provides code execution within the context of the target process, potentially inheriting its privileges and evading process-based detections. The technique is commonly used for defense evasion and privilege escalation.

Microsoft's mavinject.exe (Microsoft Application Virtualization Injector) is a legitimate signed binary that can perform DLL injection, making it attractive to attackers as a "living off the land" technique. The detection community focuses on monitoring mavinject.exe usage, process access patterns with injection-capable access rights, and suspicious DLL loads into unexpected processes.

## What This Dataset Contains

This dataset captures a complete execution of DLL injection using mavinject.exe. The key events include:

**Process Creation Chain (Security 4688/Sysmon 1):**
- Initial PowerShell execution with the command: `"powershell.exe" & {$mypid = (Start-Process notepad -PassThru).id; mavinject $mypid /INJECTRUNNING "C:\AtomicRedTeam\atomics\T1055.001\src\x64\T1055.001.dll"; Stop-Process -processname notepad}`
- Notepad.exe creation (PID 19396): `"C:\Windows\system32\notepad.exe"`
- Mavinject.exe execution (PID 18900): `"C:\Windows\system32\mavinject.exe" 19396 /INJECTRUNNING C:\AtomicRedTeam\atomics\T1055.001\src\x64\T1055.001.dll`

**Process Access Events (Sysmon 10):**
- PowerShell accessing notepad.exe with 0x1F3FFF access rights (PROCESS_ALL_ACCESS minus PROCESS_SET_INFORMATION)
- Multiple process access events showing cross-process interaction patterns typical of injection preparation

**PowerShell Script Blocks (4104):**
The actual technique command is captured: `$mypid = (Start-Process notepad -PassThru).id; mavinject $mypid /INJECTRUNNING "C:\AtomicRedTeam\atomics\T1055.001\src\x64\T1055.001.dll"; Stop-Process -processname notepad`

**Process Terminations (Security 4689):**
- Mavinject.exe exits with status 0x30005 (indicating an error condition)
- Notepad.exe exits with status 0xFFFFFFFF (process terminated externally)

## What This Dataset Does Not Contain

The injection attempt appears to have failed - mavinject.exe exited with error code 0x30005, likely due to Windows Defender or other security controls blocking the DLL load. Consequently, this dataset lacks:

- Successful DLL loading events (Sysmon 7) showing the malicious DLL loaded into the target process
- Network connections or other post-injection activity
- Evidence of successful code execution within the target process
- Memory allocation or thread creation events that would indicate successful injection

The sysmon-modular configuration's include-mode filtering means we don't see ProcessCreate events for standard processes like notepad.exe in Sysmon, though they are captured in Security 4688 events.

## Assessment

This dataset provides excellent telemetry for detecting mavinject.exe-based injection attempts, even when they fail. The combination of Security 4688 process creation events with full command lines, Sysmon process access events, and PowerShell script block logging creates a comprehensive detection opportunity. The failure mode (error exit codes) actually makes this more valuable for understanding how defensive tools interact with injection attempts.

The data sources are strong for this technique - command-line auditing captures the injection command, Sysmon 10 events show the process access patterns, and Sysmon 1 events identify the mavinject.exe execution with full arguments including the target PID and DLL path.

## Detection Opportunities Present in This Data

1. **Mavinject.exe execution monitoring** - Security 4688 events show mavinject.exe with `/INJECTRUNNING` parameter and DLL path in command line
2. **PowerShell script block detection** - Event 4104 contains the full injection command including Start-Process, mavinject call, and process cleanup
3. **Process access pattern detection** - Sysmon 10 events showing PowerShell accessing other processes with high-privilege access rights (0x1F3FFF)
4. **Suspicious parent-child relationships** - PowerShell spawning mavinject.exe with injection parameters
5. **Cross-process access correlation** - PowerShell accessing both the target process (notepad) and the injection tool (mavinject)
6. **DLL path analysis** - Command lines containing references to non-standard DLL locations (`C:\AtomicRedTeam\atomics\T1055.001\src\x64\T1055.001.dll`)
7. **Process termination correlation** - Error exit codes from mavinject.exe (0x30005) indicating blocked injection attempts
8. **Rapid process lifecycle** - Short-lived notepad.exe process created solely for injection target purposes
