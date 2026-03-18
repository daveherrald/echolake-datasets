# T1218.011-10: Rundll32 — Execution of non-dll using rundll32.exe

## Technique Context

T1218.011 represents the abuse of rundll32.exe, a legitimate Windows utility designed to load and execute DLL files. Attackers frequently leverage rundll32.exe as a defense evasion technique because it allows execution of arbitrary code while appearing as a trusted Windows process. The technique is particularly valuable for bypassing application allowlisting and execution policies.

This specific test (T1218.011-10) demonstrates a common attack pattern where rundll32.exe is used to execute a non-DLL file by treating it as a DLL. The detection community focuses heavily on unusual rundll32.exe command lines, particularly those referencing files with non-DLL extensions, missing export functions, or suspicious file paths. Rundll32.exe normally requires both a DLL path and an export function name, so deviations from this pattern often indicate malicious activity.

## What This Dataset Contains

The dataset captures a PowerShell-initiated execution of rundll32.exe attempting to load a PNG file as a DLL. The key evidence includes:

**Process Creation Chain (Security 4688 & Sysmon 1):**
- Initial PowerShell process (PID 7896): `powershell.exe`
- Child PowerShell process (PID 30424): `"powershell.exe" & {rundll32.exe C:\Users\$env:username\Downloads\calc.png, StartW}`
- Rundll32 execution (PID 7808): `"C:\Windows\system32\rundll32.exe" C:\Users\ACME-WS02$\Downloads\calc.png StartW`

**PowerShell Script Block Logging (4104):**
- Script block: `& {rundll32.exe C:\Users\$env:username\Downloads\calc.png, StartW}`
- Execution context showing the malicious command being prepared and executed

**Sysmon Process Tree:**
- Sysmon EID 1 events capture the complete process ancestry from PowerShell to rundll32.exe
- Process GUIDs enable full correlation across the execution chain
- Command line arguments clearly show the attempt to execute a .png file as a DLL

**Process Access Events (Sysmon 10):**
- PowerShell accessing rundll32.exe process with full access rights (0x1FFFFF)
- Indicates potential process interaction during execution

## What This Dataset Does Not Contain

The dataset lacks several important elements that would complete the attack picture:

**No Error or Failure Telemetry:** The rundll32.exe process appears to have been created successfully, but there are no error events showing the expected failure when trying to load calc.png as a DLL. This suggests the process may have exited quickly due to the invalid DLL format.

**Missing File Access Events:** There are no Sysmon EID 11 events showing rundll32.exe attempting to access the calc.png file, which would be expected during the DLL loading attempt.

**No Registry Activity:** Rundll32.exe typically generates registry access patterns during DLL loading, but the Sysmon configuration may not capture these events.

**Limited Network Telemetry:** Only Windows Defender network connections are captured, with no network activity from the rundll32.exe process itself.

## Assessment

This dataset provides excellent telemetry for detecting T1218.011 abuse through process creation and command line monitoring. The combination of Security 4688 events with full command line logging and Sysmon process creation events creates multiple detection opportunities. The PowerShell script block logging adds valuable context about the attack preparation.

However, the dataset's strength lies primarily in the process creation phase rather than the execution outcome. For a complete understanding of rundll32.exe abuse, additional file system and error logging would strengthen the dataset. The clear process ancestry and suspicious command line arguments make this an ideal dataset for developing and testing rundll32.exe detection rules.

## Detection Opportunities Present in This Data

1. **Rundll32.exe with non-DLL file extensions** - Monitor Security 4688 and Sysmon 1 for rundll32.exe command lines referencing files with extensions other than .dll (e.g., .png, .txt, .dat)

2. **Suspicious rundll32.exe export function patterns** - Detect rundll32.exe command lines with unusual or non-standard export function names like "StartW" instead of typical DLL exports

3. **PowerShell invoking rundll32.exe with suspicious arguments** - Correlate PowerShell script block logging (4104) showing rundll32.exe execution with non-standard parameters

4. **Process ancestry analysis** - Build detections around PowerShell spawning rundll32.exe with command lines that deviate from normal administrative use cases

5. **Rundll32.exe file path anomalies** - Monitor for rundll32.exe accessing files in user directories (Downloads, Desktop, Temp) rather than system locations where legitimate DLLs typically reside

6. **Cross-reference file extensions with rundll32.exe usage** - Create rules that flag any rundll32.exe execution where the target file extension doesn't match known DLL formats

7. **PowerShell execution policy bypass detection** - The script block `Set-ExecutionPolicy Bypass` combined with rundll32.exe execution suggests potential defense evasion chains
