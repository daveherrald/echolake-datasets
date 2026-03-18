# T1202-4: Indirect Command Execution — Indirect Command Execution - ScriptRunner.exe

## Technique Context

T1202 (Indirect Command Execution) involves adversaries using trusted utilities to proxy execution of malicious code, making detection more challenging since the initial process appears legitimate. ScriptRunner.exe is a Microsoft-signed binary designed to execute scripts in App-V environments, but can be abused to launch arbitrary executables while maintaining the appearance of legitimate system activity.

The detection community focuses on unusual parent-child process relationships, command-line patterns with the `-appvscript` parameter, and cases where ScriptRunner.exe launches unexpected executables. This technique is particularly attractive to adversaries because ScriptRunner.exe is a signed Microsoft binary that can bypass application whitelisting and may evade detection rules focused on more common LOLBins.

## What This Dataset Contains

This dataset captures a successful execution of T1202-4 with complete process telemetry. The attack chain begins with PowerShell executing the command `"powershell.exe" & {Scriptrunner.exe -appvscript "C:\Windows\System32\calc.exe"}`, captured in Security event 4688. The execution creates a clear process chain:

1. PowerShell (PID 42532) spawns PowerShell (PID 6372) with command line `"powershell.exe" & {Scriptrunner.exe -appvscript \"C:\Windows\System32\calc.exe\"`
2. PowerShell (PID 6372) spawns ScriptRunner.exe (PID 31184) with `"C:\Windows\system32\ScriptRunner.exe" -appvscript C:\Windows\System32\calc.exe`
3. ScriptRunner.exe spawns calc.exe (PID 31420) with clean exit status 0x0

Sysmon provides rich process creation events (EID 1) for both ScriptRunner.exe and whoami.exe (a discovery command executed during the test), along with image load events (EID 7) showing .NET runtime initialization. PowerShell script block logging (EID 4104) captures the exact command: `& {Scriptrunner.exe -appvscript "C:\Windows\System32\calc.exe"}` and `{Scriptrunner.exe -appvscript "C:\Windows\System32\calc.exe"}`.

Process access events (EID 10) show PowerShell accessing both the newly created processes, indicating normal process monitoring behavior. The technique executed successfully with all processes exiting cleanly.

## What This Dataset Does Not Contain

The dataset lacks network activity since calc.exe is a benign local executable. There are no blocked execution events or Defender alerts, indicating Windows Defender did not flag this as malicious activity. The PowerShell events contain mostly test framework boilerplate with Set-StrictMode and Set-ExecutionPolicy commands rather than complex malicious scripts.

File creation events are limited to PowerShell profile-related files, with no suspicious file drops or persistence mechanisms. Registry modification events are absent since this technique doesn't require registry changes. The sysmon-modular config's include-mode filtering captured ScriptRunner.exe as a known suspicious binary, but standard applications like calc.exe may not trigger Sysmon process creation events in all configurations.

## Assessment

This dataset provides excellent telemetry for detecting T1202-4 abuse of ScriptRunner.exe. The combination of Security 4688 events with full command-line logging and Sysmon process creation events creates multiple detection opportunities. The clear parent-child process relationships, distinctive command-line parameters, and PowerShell script block logging make this technique highly detectable in well-instrumented environments.

The data quality is strong for building behavioral detections focused on ScriptRunner.exe usage patterns, unusual parent processes, and the `-appvscript` parameter. However, detection engineers should note that this benign test case may not represent the full range of evasion techniques adversaries might employ, such as obfuscated command lines or execution of more sophisticated payloads.

## Detection Opportunities Present in This Data

1. **ScriptRunner.exe Process Creation** - Monitor Sysmon EID 1 and Security EID 4688 for ScriptRunner.exe execution, especially with the `-appvscript` parameter from unusual parent processes

2. **Unusual Parent-Child Relationships** - Detect PowerShell spawning ScriptRunner.exe, particularly when the command line contains `-appvscript` followed by executable paths

3. **Command Line Analysis** - Alert on command lines matching patterns like `ScriptRunner.exe -appvscript` combined with paths to executables outside typical script directories

4. **PowerShell Script Block Logging** - Monitor PowerShell EID 4104 for script blocks containing `Scriptrunner.exe` invocations with suspicious parameters

5. **Process Chain Analysis** - Build detections for process trees where ScriptRunner.exe serves as an intermediary between PowerShell and system executables

6. **System Binary Proxy Execution** - Leverage Sysmon's T1218 rule name tagging to identify ScriptRunner.exe as part of system binary proxy execution attempts

7. **Cross-Reference with Process Access** - Correlate Sysmon EID 10 process access events to identify when PowerShell accesses ScriptRunner.exe processes, indicating potential process injection or monitoring
