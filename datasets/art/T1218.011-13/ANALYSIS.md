# T1218.011-13: Rundll32 — Rundll32 with desk.cpl

## Technique Context

T1218.011 (Rundll32) is a defense evasion technique where adversaries abuse the legitimate Windows rundll32.exe utility to execute malicious code. Rundll32.exe is designed to execute functions within Dynamic Link Libraries (DLLs), making it a powerful proxy execution mechanism. The detection community focuses on unusual rundll32 command lines, especially those invoking uncommon DLLs, suspicious export functions, or file paths that deviate from normal Windows operations.

This specific test demonstrates using rundll32 to execute desk.cpl's InstallScreenSaver function, which is designed to install and preview screensavers. By copying calc.exe to not_an_scr.scr and invoking it through this mechanism, the technique achieves proxy execution while masquerading the payload as a screensaver file. This approach combines multiple MITRE ATT&CK techniques: T1218.011 (Rundll32), T1036 (Masquerading), and leverages the legitimate Windows screensaver installation functionality.

## What This Dataset Contains

The dataset captures a complete rundll32-based execution chain initiated by PowerShell. The key events show:

**Process Creation Chain (Security Events 4688):**
- Initial PowerShell process (PID 35848): `powershell.exe`
- Command execution: `"cmd.exe" /c copy %windir%\System32\calc.exe not_an_scr.scr & rundll32.exe desk.cpl,InstallScreenSaver not_an_scr.scr`
- Rundll32 execution (PID 34152): `rundll32.exe desk.cpl,InstallScreenSaver not_an_scr.scr`
- Final payload execution (PID 29032): `not_an_scr.scr /p 131338`

**File Operations (Sysmon Event 11):**
- File creation: `C:\Windows\Temp\not_an_scr.scr` by cmd.exe, showing the copying of calc.exe

**Sysmon Process Events:**
- Sysmon EID 1 captures all process creations with full command lines and process relationships
- Shows the masquerading aspect with calc.exe renamed to not_an_scr.scr
- Captures the screensaver preview parameters (`/p 131338`)

**Image Load Events (Sysmon Event 7):**
- Multiple DLL loads for rundll32.exe including urlmon.dll
- Image load of the masqueraded executable showing its true identity as calc.exe

## What This Dataset Does Not Contain

The dataset lacks several elements that could strengthen detection coverage:

**Registry Activity:** No registry events show the typical screensaver installation registry writes that desk.cpl normally performs, suggesting the InstallScreenSaver function may have different behavior when used this way.

**Network Activity:** While there's a Windows Defender telemetry connection, there's no network activity from the actual technique execution.

**Module Loads:** Limited visibility into which specific desk.cpl functions are loaded during rundll32 execution.

**Process Termination Details:** While Security event 4689 shows process exits, there's limited detail about how the screensaver preview mode terminated.

## Assessment

This dataset provides excellent telemetry for detecting rundll32 abuse, particularly the desk.cpl variant. The combination of Security 4688 events with full command-line logging and Sysmon process creation events offers comprehensive coverage of the execution chain. The file creation events clearly show the masquerading technique, and the complete parent-child process relationships enable detection of the entire attack sequence.

The data quality is particularly strong for building detections around unusual rundll32 command lines, file masquerading, and screensaver abuse. The presence of both the legitimate Windows calculator execution and its masqueraded invocation provides clear indicators of malicious behavior.

## Detection Opportunities Present in This Data

1. **Rundll32 with desk.cpl and non-standard screensaver files** - Monitor for `rundll32.exe desk.cpl,InstallScreenSaver` with file arguments that don't match typical .scr extensions or are in unusual locations like TEMP directories.

2. **File copying to screensaver extensions** - Detect copy operations where executables are renamed to .scr extensions, especially when followed by rundll32 desk.cpl execution.

3. **Screensaver files with mismatched metadata** - Alert on .scr files with OriginalFileName values that don't match screensaver applications (e.g., CALC.EXE in a .scr file).

4. **Unusual screensaver execution locations** - Monitor for screensaver files executing from non-standard paths like TEMP directories rather than typical system screensaver locations.

5. **Process chain analysis** - Detect the specific sequence: cmd.exe copy operation → rundll32.exe desk.cpl → .scr execution with process lineage validation.

6. **Command line pattern matching** - Build signatures for the combined copy and rundll32 command pattern: `copy [source] [target].scr & rundll32.exe desk.cpl,InstallScreenSaver [target].scr`.

7. **Masquerading detection via file hash correlation** - Cross-reference file hashes of .scr files with known legitimate executables to identify masquerading.
