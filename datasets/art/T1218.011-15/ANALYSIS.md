# T1218.011-15: Rundll32 — Rundll32 execute command via FileProtocolHandler

## Technique Context

T1218.011 (Rundll32) is a defense evasion technique where attackers abuse rundll32.exe to proxy execution of malicious code. Rundll32 is a legitimate Windows utility that loads and runs 32-bit Dynamic Link Libraries (DLLs) from the command line. Attackers commonly leverage rundll32 to execute malicious payloads while appearing to run a trusted system binary. The FileProtocolHandler export in url.dll is particularly notable because it can be used to launch arbitrary executables, effectively turning rundll32 into a process launcher that bypasses some application whitelisting solutions. Detection engineers focus on unusual rundll32 command lines, especially those calling url.dll exports or other suspicious DLL/export combinations, and process chains where rundll32 spawns unexpected child processes.

## What This Dataset Contains

This dataset captures a successful rundll32.exe abuse using the FileProtocolHandler technique to launch calc.exe. The attack chain is clearly visible in the telemetry:

**Process Chain**: PowerShell → cmd.exe → rundll32.exe → calc.exe

Key events include:
- **Security 4688**: Process creation of `cmd.exe` with command line `"cmd.exe" /c rundll32.exe url.dll,FileProtocolHandler calc.exe`
- **Security 4688**: Process creation of `rundll32.exe` with command line `rundll32.exe  url.dll,FileProtocolHandler calc.exe`
- **Security 4688**: Process creation of `calc.exe` with command line `"C:\Windows\System32\calc.exe"`
- **Sysmon 1**: Process creation events for cmd.exe, rundll32.exe (with RuleName matching T1218.011), and calc.exe showing the complete parent-child relationships
- **Sysmon 7**: Image load of urlmon.dll in both rundll32.exe and calc.exe processes
- **Sysmon 10**: Process access events showing PowerShell accessing both cmd.exe and whoami.exe processes

The command line clearly shows the classic FileProtocolHandler syntax with url.dll being called to launch calc.exe. All processes executed successfully with exit status 0x0.

## What This Dataset Does Not Contain

The dataset does not show any defensive blocking - Windows Defender allowed the technique to execute completely. There are no failed process creation events or access denied errors that would indicate endpoint protection interference. The PowerShell events contain only boilerplate test framework code (Set-StrictMode, Set-ExecutionPolicy Bypass) rather than the actual attack commands. No network connections are present since this is purely a local execution technique. Registry modifications that might accompany more sophisticated rundll32 abuse are not captured here.

## Assessment

This dataset provides excellent coverage for T1218.011 detection engineering. The combination of Security 4688 process creation logs with full command-line logging and Sysmon ProcessCreate events captures the complete attack chain with high fidelity. The presence of both parent-child process relationships and the specific rundll32 command line syntax makes this ideal for developing behavioral detections. The successful execution without defensive interference provides clean telemetry showing exactly what attackers achieve with this technique. The Sysmon configuration's inclusion of rundll32.exe in its process creation rules ensures comprehensive coverage of this Living Off the Land Binary (LOLBin) abuse.

## Detection Opportunities Present in This Data

1. **Rundll32 FileProtocolHandler Usage**: Alert on rundll32.exe command lines containing "url.dll,FileProtocolHandler" followed by executable names or paths.

2. **Rundll32 Spawning Executables**: Detect rundll32.exe as a parent process creating child processes, especially common utilities like calc.exe, notepad.exe, or cmd.exe.

3. **Command Line Pattern Matching**: Hunt for rundll32.exe with url.dll exports being called with executable arguments rather than typical URL protocols.

4. **Process Chain Analysis**: Identify suspicious process lineages where script interpreters (PowerShell/cmd) spawn rundll32.exe which then spawns unexpected child processes.

5. **Rundll32 URL.dll Export Abuse**: Monitor for rundll32.exe loading url.dll combined with process creation events indicating executable launching rather than URL handling.

6. **LOLBin Process Access Patterns**: Detect when script processes (PowerShell) gain high-privilege access (0x1FFFFF) to rundll32.exe spawned processes, indicating potential process injection preparation.
