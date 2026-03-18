# T1216-2: System Script Proxy Execution — manage-bde.wsf Signed Script Command Execution

## Technique Context

T1216.002 is a System Script Proxy Execution technique that abuses Microsoft's signed manage-bde.wsf Windows Script File to execute arbitrary commands. The manage-bde.wsf script is a legitimate Microsoft-signed file used for BitLocker management that can be manipulated via environment variables to proxy command execution. Attackers leverage this by setting the COMSPEC environment variable to point to their desired executable, causing manage-bde.wsf to execute the attacker's binary instead of cmd.exe when the script calls shell commands internally.

This technique provides defense evasion by using a trusted, signed Microsoft script to execute commands, potentially bypassing application whitelisting and script execution policies. Detection engineers typically focus on unusual COMSPEC modifications, cscript.exe execution of manage-bde.wsf with suspicious parent processes, and the resulting child process execution chains that deviate from normal BitLocker operations.

## What This Dataset Contains

This dataset captures a successful T1216.002 execution with excellent telemetry coverage across multiple data sources. The attack chain begins with PowerShell executing the command: `"cmd.exe" /c set comspec=%windir%\System32\calc.exe & cscript %windir%\System32\manage-bde.wsf`.

**Process Chain Evidence:**
- Security EID 4688 shows cmd.exe execution with the malicious command line setting COMSPEC to calc.exe
- Sysmon EID 1 captures cscript.exe (PID 20912) spawning from cmd.exe to execute manage-bde.wsf
- The final payload execution shows calc.exe (PID 20896) launched from cscript.exe with arguments `/c manage-bde.exe -legacy_Vista`

**Key Indicators:**
- COMSPEC environment variable manipulation: `set comspec=%windir%\System32\calc.exe`
- Microsoft-signed cscript.exe executing manage-bde.wsf: `cscript C:\Windows\System32\manage-bde.wsf`
- Calc.exe masquerading as cmd.exe via COMSPEC redirection
- Process access events (EID 10) showing PowerShell accessing both whoami.exe and cmd.exe child processes

**Script Host Activity:**
Sysmon EID 7 events show cscript.exe loading VBScript runtime libraries (vbscript.dll, scrrun.dll, wshom.ocx) and Windows Defender AMSI integration (amsi.dll, MpOAV.dll), indicating active script execution monitoring.

## What This Dataset Does Not Contain

The PowerShell events contain only boilerplate test framework activity (Set-StrictMode, Set-ExecutionPolicy Bypass) rather than the actual attack commands, as the technique execution occurs through cmd.exe and cscript.exe rather than PowerShell directly.

The dataset lacks registry access events that might show environment variable modifications, as the COMSPEC setting appears to be process-scoped rather than persistent. Network activity is absent since this is a local command execution technique.

File system events beyond PowerShell startup profiles are minimal - the technique doesn't create or modify files on disk, making it particularly stealthy from a file-based detection perspective.

## Assessment

This dataset provides excellent visibility into T1216.002 execution across multiple telemetry sources. The Security channel's command-line logging captures the COMSPEC manipulation clearly, while Sysmon process creation events show the complete execution chain with parent-child relationships. The process access events add additional context about PowerShell's interaction with spawned processes.

The combination of Security EID 4688 and Sysmon EID 1 events provides complementary coverage - Security captures all process creation with full command lines while Sysmon adds detailed metadata, hashes, and process relationships. The image load events show the legitimate Microsoft components being used, which helps distinguish this technique from pure malware execution.

This telemetry quality makes it highly suitable for developing behavioral detections focused on the COMSPEC manipulation pattern and unusual cscript.exe usage of manage-bde.wsf.

## Detection Opportunities Present in This Data

1. **COMSPEC Environment Variable Manipulation** - Security EID 4688 command line contains `set comspec=` followed by non-cmd.exe executable paths, indicating environment variable abuse

2. **Suspicious cscript.exe Execution of manage-bde.wsf** - Sysmon EID 1 showing cscript.exe executing manage-bde.wsf from unexpected parent processes or with unusual timing patterns

3. **Abnormal Process Chain for BitLocker Operations** - Process trees where manage-bde.wsf execution results in calc.exe or other non-BitLocker binaries as child processes

4. **COMSPEC Redirection Detection** - Command lines showing legitimate Windows utilities (cmd.exe) being replaced with arbitrary executables in the same command sequence

5. **Script Host Runtime Loading Anomalies** - Sysmon EID 7 showing cscript.exe loading VBScript libraries when manage-bde.wsf execution occurs outside normal system administration contexts

6. **Process Access Pattern Analysis** - Sysmon EID 10 events showing PowerShell or other processes accessing cscript.exe children with high privileges (0x1FFFFF), indicating potential process injection preparation

7. **Parent-Child Process Relationship Violations** - Sysmon process GUIDs showing calc.exe spawning from cscript.exe executing manage-bde.wsf, which violates expected BitLocker operation patterns
