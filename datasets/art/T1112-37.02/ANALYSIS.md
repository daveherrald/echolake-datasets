# T1112-37: Modify Registry — Disable Windows Security Center Notifications

## Technique Context

T1112 (Modify Registry) is a defense evasion and persistence technique in which adversaries write Windows registry values to undermine security visibility, suppress alerts, or alter system behavior. This test targets the Windows Security Center notification system — specifically the `UseActionCenterExperience` value in `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\ImmersiveShell` — setting it to `0` to disable Action Center notifications.

Windows Security Center surfaces user-visible alerts when security controls are degraded: antivirus disabled, firewall off, updates overdue, or other health warnings. By suppressing these notifications, an attacker reduces the chance that a user or administrator will notice that the security posture has been tampered with. This technique is commonly combined with other defense-evasion steps — disabling Defender's real-time monitoring, excluding directories, or manipulating firewall policies — to leave the system in a weakened state without triggering visible warnings.

The `WOW6432Node` path is the 32-bit registry view on 64-bit Windows, and ImmersiveShell controls aspects of the Windows shell experience including notification behaviors.

In the defended variant, this dataset produced 36 Sysmon, 12 Security, and 34 PowerShell events. The undefended capture produced 17 Sysmon, 4 Security, and 93 PowerShell events. The PowerShell event count increase in the undefended variant reflects more verbose ART test framework logging without interference; the Security event reduction reflects the absence of Defender-triggered child process activity.

## What This Dataset Contains

The technique execution is captured through the process creation chain. Sysmon EID 1 shows `cmd.exe` (PID 3700) spawned by PowerShell (PID 3620) with the full command:

```
"cmd.exe" /c reg add HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\ImmersiveShell /v UseActionCenterExperience /t REG_DWORD /d 0 /f
```

`cmd.exe` then spawned `reg.exe` (PID 7096) with:

```
reg  add HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\ImmersiveShell /v UseActionCenterExperience /t REG_DWORD /d 0 /f
```

Security EID 4688 independently records both process creations with full command lines. The Creator Process for `cmd.exe` is PowerShell (`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`). All executions run under `NT AUTHORITY\SYSTEM`.

Sysmon EID 7 (image load) records multiple DLL loads into PowerShell's process, tagged with `technique_id=T1055,technique_name=Process Injection`, `technique_id=T1059.001,technique_name=PowerShell`, and `technique_id=T1574.002,technique_name=DLL Side-Loading`. Sysmon EID 10 (process access) shows PowerShell accessing child processes.

The PowerShell channel contains 93 EID 4104 script block events. Most are boilerplate from the ART test framework (`Set-StrictMode`, `Set-ExecutionPolicy Bypass`, `Import-Module`), plus cleanup calls to `Invoke-AtomicTest T1112 -TestNumbers 37 -Cleanup`. The actual `reg add` command was not executed directly in PowerShell — it was passed through `cmd.exe` — so no script block captures the registry modification command itself.

## What This Dataset Does Not Contain

There are no Sysmon EID 12 or EID 13 events in this dataset. The sysmon-modular configuration does not monitor the `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\ImmersiveShell` path for registry changes. This means the actual value write is not directly recorded in Sysmon telemetry — you can observe the intent from command-line arguments, but not the outcome in registry telemetry.

The PowerShell script blocks do not contain the registry modification command. The ART test framework invoked `cmd.exe` as an intermediary, so the `reg add` call never appeared as a PowerShell cmdlet that would be logged in EID 4103 or as a script block in EID 4104.

There is no Security Center event log activity, no WMI events, and no application log entries corroborating that notifications were disabled. Verification of success would require querying the registry value directly.

The dataset does not show what other security controls were modified in the same session — this test ran in sequence with other T1112 atomics, but each dataset captures only its own execution window.

## Assessment

This dataset's detection value rests primarily on the process execution chain rather than registry telemetry. The command line captured in both Security EID 4688 and Sysmon EID 1 contains the complete `reg add` invocation with all arguments, making the attacker's intent unambiguous. However, the absence of EID 13 means a registry-monitoring-focused detection approach would miss this particular modification unless it covers the `WOW6432Node\ImmersiveShell` path.

Compared to the defended variant, the undefended execution is structurally identical — same process chain, same command line, same SYSTEM context. The difference is the absence of any Defender-triggered activity interrupting the sequence and a higher PowerShell event count from the more active test framework logging.

The technique is complete and effective in this dataset: the `reg add` command ran successfully under SYSTEM with no observable interference.

## Detection Opportunities Present in This Data

**`reg.exe` command line targeting ImmersiveShell.** The value name `UseActionCenterExperience` and the DWORD value `0` combined with the `WOW6432Node\Microsoft\Windows\CurrentVersion\ImmersiveShell` path are uncommon in legitimate administrative activity. The specific command line is present in both Sysmon EID 1 and Security EID 4688.

**PowerShell → cmd.exe → reg.exe chain under SYSTEM.** Three-hop execution with TEMP working directory (`C:\Windows\TEMP\` for cmd.exe, `C:\Windows\Temp\` for reg.exe) and SYSTEM token is consistent with automated scripted execution rather than interactive administration.

**Action Center / Security Center tamper pattern.** Monitoring for any write to ImmersiveShell values that control shell notification behavior, particularly when the process chain does not originate from a known software installer, is a reliable behavioral pattern.

**Timing proximity to other T1112 atomics.** In the broader session context, this test ran seconds after T1112-34. Sequential `reg add` executions targeting distinct security-relevant registry paths within a narrow time window are a strong behavioral cluster indicator.
