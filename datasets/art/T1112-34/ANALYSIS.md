# T1112-34: Modify Registry — Windows Add Registry Value to Load Service in Safe Mode without Network

## Technique Context

T1112 (Modify Registry) is a defense evasion and persistence technique where adversaries modify Windows registry keys to alter system behavior, disable security controls, or establish persistence. This specific test demonstrates creating a registry key under `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal\` to ensure a service loads during safe mode boot. Safe mode persistence is particularly valuable to adversaries because it allows malware to survive system recovery attempts and security tool scanning that users might perform when troubleshooting infected systems.

The detection community focuses on monitoring registry modifications to sensitive paths, especially those related to boot processes, safe mode configurations, and security settings. Registry telemetry from Sysmon Event ID 13 is critical for detecting these modifications, as process-based detection alone may miss the actual registry changes.

## What This Dataset Contains

This dataset captures the complete execution chain of the Atomic Red Team test. The core technique evidence is found in Sysmon Event ID 13, which records the registry modification:

```
Registry value set:
TargetObject: HKLM\System\CurrentControlSet\Control\SafeBoot\Minimal\AtomicSafeMode\(Default)
Details: Service
```

The execution chain is well-documented through Security Event ID 4688 process creation events:
- PowerShell spawns `cmd.exe` with command line: `"cmd.exe" /c REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal\AtomicSafeMode" /VE /T REG_SZ /F /D "Service"`
- cmd.exe spawns `reg.exe` with command line: `REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal\AtomicSafeMode" /VE /T REG_SZ /F /D "Service"`

Sysmon captures the process creation events for both cmd.exe (EID 1) and reg.exe (EID 1) with full command lines, showing the complete attack path. Sysmon Event ID 10 captures PowerShell accessing both child processes, indicating process monitoring behavior typical of command execution frameworks.

The PowerShell channel contains only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) without capturing the actual registry modification commands.

## What This Dataset Does Not Contain

The dataset lacks several elements that would provide additional detection value. There are no Sysmon ProcessCreate events for the initial PowerShell processes (PIDs 25968 and 8400) due to the sysmon-modular configuration's include-mode filtering, which only captures processes matching known-suspicious patterns. While reg.exe and cmd.exe are captured, the parent PowerShell processes are not directly visible in Sysmon ProcessCreate events.

The test does not generate network connections, file system artifacts beyond PowerShell startup files, or additional registry modifications that might occur in real-world safe mode persistence scenarios. Windows Defender was active but did not block this registry modification, as it's not inherently malicious without additional context.

## Assessment

This dataset provides excellent telemetry for detecting safe mode persistence techniques. The Sysmon Event ID 13 registry modification event is the gold standard for this detection, capturing the exact registry path and value that constitutes the malicious activity. The Security channel's process creation events with command-line logging provide strong complementary evidence showing the execution method.

The combination of process telemetry showing reg.exe execution with specific safe boot parameters, plus the registry modification itself, creates multiple detection opportunities with low false positive potential. The technique is well-represented despite missing some process creation events in Sysmon.

## Detection Opportunities Present in This Data

1. **Registry modification to SafeBoot paths** - Monitor Sysmon Event ID 13 for `TargetObject` containing `HKLM\System\CurrentControlSet\Control\SafeBoot\` to detect safe mode persistence attempts.

2. **REG.exe command line patterns** - Detect Security Event ID 4688 where `ProcessName` contains `reg.exe` and `CommandLine` contains both "SafeBoot" and "ADD" keywords.

3. **Suspicious registry paths via command line** - Monitor command lines in Security Event ID 4688 containing `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal\` followed by non-standard service names.

4. **Process chain analysis** - Correlate PowerShell spawning cmd.exe spawning reg.exe with registry modification operations targeting boot configuration paths.

5. **Safe mode service registration** - Alert on registry values set to "Service" under `SafeBoot\Minimal\` paths for unknown or suspicious service names.

6. **Cross-process monitoring** - Use Sysmon Event ID 10 to detect PowerShell processes accessing reg.exe processes, indicating potential command execution monitoring or process injection preparation.
