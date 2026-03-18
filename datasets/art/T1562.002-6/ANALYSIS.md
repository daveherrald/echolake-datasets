# T1562.002-6: Disable Windows Event Logging — Disable Event Logging with wevtutil

## Technique Context

T1562.002 (Disable Windows Event Logging) covers adversary actions to prevent or degrade Windows event log collection. This test uses `wevtutil.exe` — the built-in Windows Event Log command-line utility — to disable a specific event log channel. The command `wevtutil sl "Microsoft-Windows-IKE/Operational" /e:false` disables the IPsec IKE operational log. `wevtutil` (Windows Events Utility) is a LOLBin with legitimate administrative uses, making it a lower-profile choice for log manipulation than custom tools.

## What This Dataset Contains

The dataset captures 88 events across Sysmon (38), Security (16), and PowerShell (34) channels over a six-second window.

**Sysmon Event ID 1 (process create)** captures both the cmd.exe wrapper and `wevtutil.exe` itself:

- `cmd.exe` with command line: `"cmd.exe" /c wevtutil sl "Microsoft-Windows-IKE/Operational" /e:false`
- `wevtutil.exe` with command line: `wevtutil sl "Microsoft-Windows-IKE/Operational" /e:false`

The `wevtutil.exe` process create is captured because the sysmon-modular include-mode configuration includes rules matching `wevtutil.exe` (as part of its LOLBin/known-suspicious patterns coverage), giving Sysmon direct visibility into this binary even though `cmd.exe` children are not generally captured.

**Sysmon Event ID 13 (registry value set)** records the direct result of the `wevtutil sl /e:false` command:

```
Registry value set
Image: C:\Windows\System32\svchost.exe
TargetObject: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IKE/Operational\Enabled
Details: DWORD (0x00000000)
User: NT AUTHORITY\LOCAL SERVICE
```

This is the Windows Event Log service (`svchost.exe`) propagating the configuration change to the registry after receiving the instruction from `wevtutil.exe`. The registry write is made by the service rather than by `wevtutil.exe` directly.

**Security 4688/4689** records process creates and exits for `cmd.exe`, `wevtutil.exe`, `powershell.exe`, and `conhost.exe` under SYSTEM, with exit status `0x0` for all, confirming success.

**PowerShell 4104** records the test framework invocation. The `wevtutil` command appears in Security 4688 and Sysmon 1 rather than in a script block since it is executed by `cmd.exe`.

## What This Dataset Does Not Contain (and Why)

There are no Windows Event Log channel disable events beyond the registry change. The event log service does not generate a dedicated event when a channel is disabled through `wevtutil` — the only operational record is the registry modification captured by Sysmon 13.

There are no Security 4719 events. Disabling a specific log channel with `wevtutil` does not modify the audit policy (which is the domain of `auditpol`). The `wevtutil sl /e:false` operation affects the channel's operational state rather than the audit subcategory configuration.

Object access auditing is not enabled, so no 4656/4663 events for the registry key modification appear in the Security log. The Sysmon 13 event is the sole record of the registry state change.

## Assessment

The technique executed successfully. Both the process create for `wevtutil.exe` and the resulting registry modification are captured. The `Microsoft-Windows-IKE/Operational` channel is an operational log covering IPsec IKE activity, not a primary security log — the choice of target is tactical, avoiding the high-value Security or System channels that would be more immediately obvious.

This dataset illustrates a case where Sysmon's include-mode filter successfully captures `wevtutil.exe` despite not capturing all child processes of `cmd.exe`, and where Sysmon registry monitoring catches the downstream effect of the command.

## Detection Opportunities Present in This Data

- **Sysmon 1 (process create):** `wevtutil.exe` with `sl` (set log) and `/e:false` arguments is a direct detection. Any use of `wevtutil sl ... /e:false` or `/e:0` should be alerted.
- **Security 4688:** Same `wevtutil sl` command line visible in process creation telemetry — provides coverage independent of Sysmon filter configuration.
- **Sysmon 13 (registry value set):** The key `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\<channel name>\Enabled` being set to `0x00000000` by `svchost.exe` is a reliable indicator of channel disabling. Monitoring any writes to `WINEVT\Channels\*\Enabled` with value `0` provides coverage even if the `wevtutil` process create is missed.
- **Parent-child:** `cmd.exe` spawning `wevtutil.exe` from `C:\Windows\TEMP\` under SYSTEM context is suspicious.
- **Channel selection:** Monitoring for disabling of any channels beyond rarely-used operational logs (especially Security, System, Sysmon Operational, PowerShell Operational) provides prioritized alerting.
