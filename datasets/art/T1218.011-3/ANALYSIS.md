# T1218.011-3: Rundll32 — Rundll32 execute VBscript command using Ordinal number

## Technique Context

T1218.011 (Rundll32) is a defense evasion technique where attackers abuse the legitimate Windows rundll32.exe utility to execute malicious code while appearing benign to security controls. Rundll32 is designed to execute functions from DLLs, but attackers exploit its flexibility to load and execute arbitrary code through various methods including inline VBScript, JavaScript, and URL schemes.

This specific test demonstrates rundll32 executing VBScript code using an ordinal number reference (#135) to mshtml.dll. The technique leverages rundll32's ability to call functions by ordinal number rather than by name, making the execution less obvious in command-line analysis. The VBScript creates a WScript.Shell object and executes calc.exe, a common proof-of-concept payload. Detection engineers focus on suspicious rundll32 command lines, especially those containing script engines (vbscript:, javascript:), unusual DLL references, or ordinal numbers.

## What This Dataset Contains

This dataset captures a successful rundll32 VBScript execution with complete process telemetry:

**Primary execution chain (Security 4688 events):**
- PowerShell → cmd.exe `/c rundll32 vbscript:"\..\mshtml,#135 "+String(CreateObject("WScript.Shell").Run("calc.exe"),0)`
- cmd.exe → rundll32 `vbscript:"\..\mshtml,#135 "+String(CreateObject("WScript.Shell").Run("calc.exe"),0)`
- rundll32 → calc.exe (successful payload execution)

**Sysmon ProcessCreate events (EID 1):**
- whoami.exe execution (PID 31372) from PowerShell with command line `"C:\Windows\system32\whoami.exe"`
- cmd.exe (PID 5624) with the full rundll32 VBScript command
- rundll32.exe (PID 18792) with the VBScript payload
- No calc.exe ProcessCreate event captured (filtered by sysmon-modular include rules)

**Key DLL loading activity (Sysmon EID 7):**
- rundll32 loading `urlmon.dll`, `vbscript.dll`, `wshom.ocx` (Windows Script Host), and `scrrun.dll` (Script Runtime)
- AMSI integration via `amsi.dll` loading in rundll32
- Windows Defender integration through `MpOAV.dll` and `MpClient.dll`

**Process access events (Sysmon EID 10):**
- PowerShell accessing both whoami.exe and cmd.exe with full access rights (0x1FFFFF)
- CallTrace showing .NET System.Management.Automation involvement

## What This Dataset Does Not Contain

The dataset lacks several expected elements:

**Missing Sysmon ProcessCreate for calc.exe:** The calc.exe execution appears in Security 4688 but not in Sysmon EID 1, indicating the sysmon-modular config's include-mode filtering doesn't capture calc.exe as a suspicious process.

**No VBScript content analysis:** While the command line shows the VBScript payload, there's no deeper inspection of the actual script execution or COM object instantiation beyond DLL loading.

**Limited network telemetry:** Only one network connection from Windows Defender, no connections related to the attack technique itself.

**No file system artifacts:** The technique executes entirely in memory without creating persistent files, which is typical for this rundll32 VBScript approach.

**Minimal PowerShell telemetry:** The PowerShell channel contains only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) rather than the actual attack execution commands.

## Assessment

This dataset provides excellent coverage for detecting T1218.011 VBScript abuse. The Security 4688 events capture the complete command-line chain with full fidelity, showing the exact VBScript payload and execution flow. The Sysmon data adds valuable context through DLL loading patterns and process access events that reveal the underlying script execution mechanisms.

The combination of suspicious rundll32 command line syntax, script engine DLL loading, and the characteristic ordinal number reference (#135) provides multiple detection vectors. The presence of both parent-child process relationships and detailed command lines makes this dataset particularly valuable for developing robust detection rules.

The only limitation is the missing calc.exe ProcessCreate in Sysmon, but this is compensated by comprehensive Security audit logs and doesn't significantly impact detection capability for the core technique.

## Detection Opportunities Present in This Data

1. **Suspicious rundll32 command lines** - Detect rundll32.exe with "vbscript:" scheme and ordinal number references like "#135"

2. **Script engine DLL loading in rundll32** - Monitor rundll32.exe loading vbscript.dll, wshom.ocx, and scrrun.dll in sequence

3. **Parent-child process anomalies** - Alert on cmd.exe spawning rundll32.exe with script-related command lines

4. **VBScript object creation patterns** - Detect command lines containing "CreateObject(" and "WScript.Shell" in rundll32 context

5. **Ordinal number DLL references** - Flag rundll32 command lines containing "#[number]" patterns, especially with mshtml.dll

6. **Process access events** - Monitor PowerShell accessing newly created processes with full access rights during script execution

7. **AMSI integration bypass attempts** - Correlate rundll32 script execution with AMSI.dll loading patterns

8. **Command line obfuscation detection** - Identify path traversal sequences like "\.." in rundll32 DLL references
