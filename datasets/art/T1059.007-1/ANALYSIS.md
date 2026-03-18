# T1059.007-1: JavaScript — JScript execution to gather local computer information via cscript

## Technique Context

T1059.007 JavaScript represents adversary use of JavaScript and JScript engines to execute malicious code on Windows systems. Attackers commonly leverage Windows Script Host (cscript.exe/wscript.exe) to execute JavaScript (.js) files for reconnaissance, persistence, or payload delivery. This technique is particularly valuable for attackers because JavaScript execution is often considered legitimate administrative activity, making detection challenging. The detection community focuses on monitoring cscript.exe/wscript.exe process creation with suspicious command lines, unusual parent processes, file system artifacts from script execution, and WMI queries performed by scripts for system reconnaissance.

## What This Dataset Contains

This dataset captures a straightforward JavaScript reconnaissance execution through the process chain: PowerShell → cmd.exe → cscript.exe. The Security event log shows the complete process tree with Security 4688 events: PowerShell (PID 22824) spawning cmd.exe with command line `"cmd.exe" /c cscript "C:\AtomicRedTeam\atomics\T1059.007\src\sys_info.js" > %tmp%\T1059.007.out.txt`, followed by cscript.exe (PID 23032) with command line `cscript "C:\AtomicRedTeam\atomics\T1059.007\src\sys_info.js"`.

Sysmon provides excellent telemetry on the cscript.exe process creation (EID 1) with RuleName matching "technique_id=T1202,technique_name=Indirect Command Execution", indicating the sysmon-modular configuration correctly flagged this as suspicious. Critical Sysmon EID 7 events show cscript.exe loading AMSI (amsi.dll) and Windows Defender components (MpOAV.dll), demonstrating security monitoring integration. Notably, cscript.exe loaded wmiutils.dll (EID 7 with RuleName "technique_id=T1047,technique_name=Windows Management Instrumentation"), indicating the JavaScript performed WMI queries for system information gathering.

Sysmon EID 11 shows file creation of `C:\Windows\Temp\T1059.007.out.txt`, capturing the output redirection from the reconnaissance script. The PowerShell events contain only test framework boilerplate (Set-ExecutionPolicy, Set-StrictMode) with no meaningful script content.

## What This Dataset Does Not Contain

The dataset lacks the actual JavaScript source code content that was executed, which would be valuable for understanding specific reconnaissance techniques. While we see WMI library loading, there are no Sysmon EID 19-21 WMI events showing the specific WMI queries performed by the script. The output file content is not captured in the logs, so we cannot see what system information was gathered. Process termination events (Security 4689) show normal exit codes (0x0), indicating successful execution without Defender intervention.

## Assessment

This dataset provides solid telemetry for detecting JavaScript-based reconnaissance through cscript.exe. The combination of Security 4688 command-line logging, Sysmon process creation with technique tagging, and image load events showing WMI library usage creates multiple detection opportunities. The sysmon-modular configuration correctly identified this activity as suspicious. While missing the script content and WMI query details, the process telemetry and file artifacts provide sufficient evidence for detection engineering purposes.

## Detection Opportunities Present in This Data

1. **cscript.exe execution with suspicious command lines** - Monitor Security 4688 or Sysmon EID 1 for cscript.exe processes executing .js files from non-standard locations like AtomicRedTeam directories

2. **cmd.exe spawning cscript.exe for file redirection** - Detect cmd.exe with /c parameter launching cscript.exe with output redirection to temp directories

3. **WMI library loading by script engines** - Monitor Sysmon EID 7 for cscript.exe/wscript.exe loading wmiutils.dll, indicating WMI-based reconnaissance

4. **Temp file creation from script execution** - Detect Sysmon EID 11 file creation events in temp directories from cscript.exe processes

5. **PowerShell spawning script engines** - Monitor for PowerShell parent processes launching cmd.exe or cscript.exe, indicating potential script-based execution

6. **AMSI integration with script engines** - Correlate Sysmon EID 7 amsi.dll loads with cscript.exe to identify scripts under security scanning

7. **Sysmon rule-based detection** - Leverage existing sysmon-modular rules that flag cscript.exe as T1202 (Indirect Command Execution) technique
