# T1218.005-2: Mshta — Mshta executes VBScript to execute malicious command

## Technique Context

T1218.005 (Mshta) is a defense evasion technique where attackers abuse Microsoft HTML Application Host (mshta.exe) to execute malicious scripts while bypassing application controls. Mshta.exe is a trusted Windows binary that can execute HTML Applications (.hta files) or inline scripts, making it an attractive living-off-the-land binary (LOLBin) for attackers. The technique is particularly valuable because mshta can execute VBScript and JScript directly from command line arguments, enabling script execution without writing files to disk. Detection engineers typically focus on unusual mshta command lines containing script execution patterns, process ancestry chains involving mshta spawning child processes, and script content analysis.

## What This Dataset Contains

This dataset captures a complete mshta-based VBScript execution chain. The attack begins with a PowerShell process (PID 41344) that spawns cmd.exe with the command line: `"cmd.exe" /c mshta vbscript:Execute("CreateObject(""Wscript.Shell"").Run ""powershell -noexit -file C:\AtomicRedTeam\atomics\T1218.005\src\powershell.ps1"":close")`. 

Security Event ID 4688 captures the full process creation chain: PowerShell → cmd.exe → mshta.exe → PowerShell. The mshta.exe process (PID 11720) is created with the complete VBScript payload visible in the command line: `mshta vbscript:Execute("CreateObject(""Wscript.Shell"").Run ""powershell -noexit -file C:\AtomicRedTeam\atomics\T1218.005\src\powershell.ps1"":close")`.

Sysmon Event ID 1 provides additional process creation details including file hashes and parent-child relationships. Sysmon EID 7 shows mshta.exe loading critical libraries: vbscript.dll (VBScript engine), wshom.ocx (Windows Script Host), amsi.dll (Anti-Malware Scan Interface), and scrrun.dll (Script Runtime). The child PowerShell process (PID 11676) successfully executes and loads the target script from `C:\AtomicRedTeam\atomics\T1218.005\src\powershell.ps1`.

PowerShell Event ID 4104 captures the execution of a simple PowerShell script containing `Get-LocalUser` and `Get-LocalGroup` commands - demonstrating successful code execution through the mshta vector.

## What This Dataset Does Not Contain

The dataset lacks network-based mshta execution scenarios, which are common in real attacks where mshta fetches and executes remote HTA files. The PowerShell payload here is benign discovery commands rather than more sophisticated post-exploitation activities that mshta typically enables. Windows Defender did not block this execution, so the dataset doesn't contain prevention telemetry. The VBScript content itself isn't logged in detail beyond what's visible in command lines - more advanced script analysis would require additional instrumentation.

## Assessment

This dataset provides excellent coverage for detecting T1218.005 mshta abuse. The Security channel's process creation events with full command-line logging capture the most critical detection points, while Sysmon adds valuable context through process ancestry, file hashes, and DLL loading patterns. The combination gives defenders multiple detection opportunities across different telemetry sources. The data quality is high with clear process chains and complete command-line arguments preserved. However, the benign nature of the payload and lack of network-based execution scenarios limits its representation of more sophisticated real-world attacks.

## Detection Opportunities Present in This Data

1. **Mshta VBScript execution pattern** - Security EID 4688 and Sysmon EID 1 showing mshta.exe with `vbscript:Execute` command line arguments containing script payloads

2. **Mshta child process spawning** - Process creation events showing mshta.exe spawning PowerShell or other interpreters, indicating successful script execution

3. **Suspicious mshta command line patterns** - Detection of embedded VBScript/JScript content in mshta process arguments, particularly `CreateObject("Wscript.Shell")` patterns

4. **PowerShell execution via mshta ancestry** - PowerShell processes with mshta.exe as parent process, indicating potential defense evasion

5. **Mshta loading scripting engines** - Sysmon EID 7 showing mshta.exe loading vbscript.dll, jscript9.dll, and Windows Script Host libraries

6. **Command line obfuscation indicators** - Multiple levels of command execution (PowerShell → cmd → mshta → PowerShell) suggesting process injection or evasion attempts

7. **Mshta AMSI interaction** - Sysmon EID 7 showing mshta loading amsi.dll, which can indicate attempts to execute potentially malicious scripts subject to AMSI scanning

8. **Inline script execution without HTA files** - Mshta execution without corresponding .hta file creation, indicating direct script execution from command line
