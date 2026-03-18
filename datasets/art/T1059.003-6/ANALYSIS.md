# T1059.003-6: Windows Command Shell — Command prompt writing script to file then executes it

## Technique Context

T1059.003 (Windows Command Shell) represents adversary use of cmd.exe and batch files for command execution. This specific test demonstrates a multi-stage attack pattern where cmd.exe writes a VBScript file to disk and then executes it via wscript.exe. This technique is commonly used by attackers to:

- Stage payloads on disk for persistence or evasion
- Chain different interpreters (cmd.exe → VBScript → additional commands)
- Bypass certain script execution policies that may block direct PowerShell or VBScript execution
- Create files that appear less suspicious than direct malicious executables

Detection engineers typically focus on file creation events for script files, process chains involving multiple interpreters, and command lines that redirect output to create executable content.

## What This Dataset Contains

The dataset captures a complete execution chain starting from PowerShell and proceeding through multiple command interpreters:

1. **Initial PowerShell execution** (PID 19076) with Security 4688 showing `powershell.exe` startup
2. **Primary cmd.exe execution** (PID 18888) with command line: `"cmd.exe" /c c:\windows\system32\cmd.exe /c cd /d %TEMP%\ & echo Set objShell = CreateObject("WScript.Shell"):Set objExec = objShell.Exec("whoami"):Set objExec = Nothing:Set objShell = Nothing > AtomicTest.vbs & AtomicTest.vbs`
3. **File creation** captured in Sysmon EID 11: `C:\Windows\Temp\AtomicTest.vbs` created by cmd.exe
4. **Child cmd.exe** (PID 18472) executing directory change: `c:\windows\system32\cmd.exe /c cd /d C:\Windows\TEMP\`
5. **VBScript execution** via Sysmon EID 1: `"C:\Windows\System32\WScript.exe" "C:\Windows\Temp\AtomicTest.vbs"`
6. **Final whoami execution** (PID 19084) spawned by wscript.exe

The Sysmon data includes comprehensive DLL loading events showing wscript.exe loading VBScript runtime libraries (vbscript.dll, wshom.ocx, scrrun.dll) and Windows Defender integration (MpOAV.dll, MpClient.dll, amsi.dll).

## What This Dataset Does Not Contain

The dataset lacks certain events due to the sysmon-modular include-mode filtering:
- No Sysmon ProcessCreate events for the initial PowerShell processes, as powershell.exe doesn't match the suspicious process patterns
- The PowerShell channel contains only test framework boilerplate (`Set-ExecutionPolicy Bypass`, `Set-StrictMode`) rather than the actual test execution commands
- No network connections or DNS queries, as this test operates entirely locally
- No registry modifications, as the technique focuses purely on file-based script execution

## Assessment

This dataset provides excellent coverage for detecting file-write-to-execute patterns in Windows Command Shell attacks. The Security 4688 events with command-line logging capture the full attack chain, while Sysmon EID 11 provides the critical file creation evidence. The combination of process creation, file creation, and DLL loading events creates multiple detection opportunities across the execution timeline. The telemetry effectively demonstrates how modern EDR capabilities can track multi-stage attacks that chain different execution environments.

## Detection Opportunities Present in This Data

1. **Script file creation patterns** - Sysmon EID 11 showing cmd.exe creating .vbs files in temp directories
2. **Command line redirection to script files** - Security 4688 detecting `echo [script_content] > filename.vbs` patterns
3. **Process chain analysis** - cmd.exe → wscript.exe → child process execution chains
4. **Temp directory script execution** - wscript.exe executing files from %TEMP% or Windows\Temp
5. **VBScript runtime loading** - Sysmon EID 7 showing vbscript.dll, wshom.ocx loading in wscript.exe processes
6. **AMSI integration events** - Sysmon EID 7 detecting amsi.dll loading in script execution contexts
7. **Multi-stage command execution** - Multiple cmd.exe processes with different command line arguments in sequence
8. **Embedded VBScript content** - Command lines containing VBScript keywords like "CreateObject", "WScript.Shell", "Exec"
