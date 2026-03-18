# T1112-49: Modify Registry — Event Viewer Registry Modification - Redirection Program

## Technique Context

T1112 Modify Registry is a defense evasion and persistence technique where adversaries modify Windows registry keys and values to evade defenses, maintain persistence, or escalate privileges. This specific test (T1112-49) demonstrates a subtle persistence mechanism targeting Event Viewer's redirection program setting. By modifying `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Event Viewer\MicrosoftRedirectionProgram`, attackers can specify an alternate program that launches when users attempt to open Event Viewer.

This technique is particularly insidious because it hijacks a legitimate administrative tool that security personnel frequently use. When an administrator or analyst attempts to open Event Viewer to investigate suspicious activity, the malicious program executes instead. The detection community focuses on monitoring registry modifications to sensitive Event Viewer keys, unusual parent-child process relationships involving Event Viewer, and unexpected program executions when administrative tools are launched.

## What This Dataset Contains

The dataset captures a complete registry modification sequence executed through PowerShell and cmd.exe. The attack chain begins with PowerShell (PID 33452) executing a command that spawns cmd.exe (PID 34724) with the command line `"cmd.exe" /c reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Event Viewer" /v MicrosoftRedirectionProgram /t REG_EXPAND_SZ /d "C:\windows\system32\notepad.exe" /f`. The cmd.exe process then creates reg.exe (PID 27852) with the exact registry modification command.

Security event 4688 shows the process creation for cmd.exe with the full command line: `reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Event Viewer" /v MicrosoftRedirectionProgram /t REG_EXPAND_SZ /d "C:\windows\system32\notepad.exe" /f`. Sysmon event 1 captures both the cmd.exe and reg.exe process creations with complete command line arguments, process GUIDs, and parent-child relationships.

The dataset also includes process access events (Sysmon EID 10) showing PowerShell accessing both the whoami.exe and cmd.exe processes with full access rights (0x1FFFFF), indicating process injection techniques. Event exits are captured through Security EID 4689, showing successful completion (exit status 0x0) of all processes involved.

## What This Dataset Does Not Contain

This dataset lacks the actual registry modification events that would typically appear in System event logs or as Sysmon EID 13 (RegistryEvent - Value Set). The sysmon-modular configuration may not capture registry modifications to this specific key, or the events may have been filtered out. Additionally, there are no subsequent Event Viewer launch attempts that would demonstrate the persistence mechanism in action.

The PowerShell script block logging (EID 4104) contains only standard test framework boilerplate with Set-StrictMode commands rather than the actual registry modification PowerShell code. This suggests the technique was executed through direct command invocation rather than PowerShell script blocks. No Windows Defender alerts or blocks are present, indicating this registry modification was not flagged as malicious by the endpoint protection system.

## Assessment

This dataset provides excellent process-level telemetry for detecting registry modification attacks targeting Event Viewer. The command-line logging in both Security and Sysmon logs captures the complete attack vector with full command arguments, making it ideal for building detections based on process creation with suspicious registry modification commands.

The process access events add valuable context about PowerShell's interaction with child processes, useful for detecting process injection techniques often used in conjunction with registry modifications. However, the absence of actual registry change events limits visibility into the persistence mechanism's success and prevents correlation-based detections that rely on registry telemetry.

For detection engineering, this dataset excels at demonstrating command-line based detection opportunities but would benefit from registry modification logs to provide complete coverage of the technique.

## Detection Opportunities Present in This Data

1. **Event Viewer Registry Key Modification**: Monitor process creation events for reg.exe with command lines containing `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Event Viewer` and `MicrosoftRedirectionProgram` value modifications.

2. **Suspicious Registry Commands via CMD**: Detect cmd.exe executing with `/c` parameter followed by registry modification commands targeting Event Viewer configuration keys.

3. **PowerShell Process Tree Analysis**: Monitor for PowerShell spawning cmd.exe which then creates reg.exe, particularly when targeting system registry locations related to administrative tools.

4. **Process Access Pattern Detection**: Alert on PowerShell processes accessing multiple child processes (whoami.exe, cmd.exe) with full access rights (0x1FFFFF), indicating potential process injection or manipulation.

5. **Administrative Tool Hijacking**: Create detections for registry modifications that could hijack legitimate administrative tools like Event Viewer, Performance Monitor, or other MMC-based utilities.

6. **Elevated Registry Modification**: Monitor for registry modifications to HKLM requiring elevated privileges, especially when executed through command-line tools rather than legitimate administrative interfaces.

7. **Command Line Obfuscation Patterns**: Detect variations of registry modification commands that target Event Viewer, including different path representations or parameter ordering that could indicate evasion attempts.
