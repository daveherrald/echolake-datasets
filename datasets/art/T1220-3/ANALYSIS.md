# T1220-3: XSL Script Processing — WMIC bypass using local XSL file

## Technique Context

T1220 XSL Script Processing is a defense evasion technique where attackers leverage legitimate Windows functionality to execute code through XSL stylesheets. This technique typically uses the XML stylesheet processing capabilities of utilities like wmic.exe, msxsl.exe, or Internet Explorer to execute embedded JScript or VBScript code. The detection community focuses on monitoring for XML/XSL file processing with unusual formats, suspicious command-line usage patterns (especially wmic with /format switches), and the loading of script execution libraries (scrrun.dll, jscript.dll) by unexpected processes.

WMIC's /FORMAT parameter is particularly abused because it allows attackers to specify custom XSL stylesheets that can contain executable script code, effectively turning a system administration tool into a code execution vector. This technique is attractive to attackers because wmic.exe is a trusted, signed Microsoft binary that often bypasses application whitelisting controls.

## What This Dataset Contains

This dataset captures a complete XSL script processing execution chain starting from PowerShell invoking cmd.exe with the malicious command line: `"cmd.exe" /c wmic process list /FORMAT:"C:\AtomicRedTeam\atomics\T1220\src\wmicscript.xsl"`. The Security 4688 events show the full process creation chain: PowerShell → cmd.exe → wmic.exe → calc.exe.

The Sysmon data provides rich detail on the technique execution. Event ID 1 (Process Create) captures the cmd.exe process with the suspicious wmic command line containing the XSL format parameter. Critically, Sysmon shows wmic.exe (ProcessId 35156) loading multiple libraries including `C:\Windows\System32\scrrun.dll` and `C:\Windows\System32\wshom.ocx` - the Windows Script Host components necessary for executing embedded script code in XSL files. The presence of these DLL loads in wmic.exe is a key indicator of XSL script processing.

The successful execution is evidenced by calc.exe being spawned as a child process of wmic.exe, demonstrating that the XSL stylesheet successfully executed its payload. Security event 4688 shows calc.exe creation with Creator Process Name as `C:\Windows\System32\wbem\WMIC.exe`.

The PowerShell events contain only standard test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) and don't capture the actual test execution commands.

## What This Dataset Does Not Contain

The dataset doesn't include the actual XSL file content that was processed, which would show the embedded script code structure. There are no file access events (Sysmon EID 11) for reading the XSL file itself, only PowerShell profile creation. Network events are absent, indicating this was a purely local file-based execution rather than remote XSL fetching. The dataset also lacks any Windows Defender blocking events, suggesting the technique executed successfully without endpoint protection interference.

Registry events are not present, so we can't observe any potential registry-based persistence or configuration changes that more sophisticated XSL-based attacks might implement.

## Assessment

This dataset provides excellent coverage for detecting T1220 XSL Script Processing. The combination of Security 4688 command-line logging and Sysmon Process Create/Image Load events creates multiple detection opportunities. The command-line evidence showing wmic with /FORMAT parameters is highly detectable, while the library loading patterns (scrrun.dll, wshom.ocx in wmic.exe) provide strong behavioral indicators even if command-line logging is disabled.

The data quality is high with full process chains, parent-child relationships, and library loading sequences preserved. The successful payload execution (calc.exe creation) confirms the technique completed rather than being blocked, providing realistic telemetry of successful attacks.

## Detection Opportunities Present in This Data

1. **Command-line detection**: Monitor for wmic.exe with /FORMAT parameter pointing to local files or unusual extensions in Security 4688 or Sysmon EID 1 events

2. **Library loading anomaly**: Detect scrrun.dll or wshom.ocx loading into wmic.exe process via Sysmon EID 7 events, as these script execution libraries are unusual for normal WMIC operations

3. **Process chain analysis**: Alert on cmd.exe spawning wmic.exe followed by unexpected child processes (like calc.exe) that deviate from normal WMI query patterns

4. **XSL file monitoring**: Watch for file access to .xsl files by wmic.exe, especially in non-standard locations or with suspicious naming patterns

5. **Parent process context**: Flag wmic.exe executions with unusual parent processes (PowerShell, cmd.exe with script-like command lines) rather than expected administrative tools

6. **Privilege escalation context**: Monitor for SYSTEM-level execution of wmic with format parameters, as shown in the Security 4703 token adjustment events, which may indicate automated or malicious usage
