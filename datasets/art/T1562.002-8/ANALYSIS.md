# T1562.002-8: Disable Windows Event Logging — PowerShell

## Technique Context

T1562.002 covers adversary actions that disable or degrade Windows event logging. This test
modifies the `ChannelAccess` registry value for a specific event log channel using PowerShell's
`Set-ItemProperty`, then forces a restart of the Windows Event Log service. The targeted key is
`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TaskScheduler/Operational`,
and the value `O:SYG:SYD:(D;;0x1;;;WD)` denies read access to the World (Everyone) SID. After
the service restarts, that log channel becomes inaccessible to non-privileged readers.

This is a targeted, registry-based technique that does not require external tooling. Ransomware
and post-exploitation frameworks use this pattern to blind defenders before destructive activity.

## What This Dataset Contains

**Sysmon (52 events):** The core telemetry. Sysmon ID 1 captures the PowerShell process launched
by the ART test framework with its full command line:

```
"powershell.exe" & {Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\
WINEVT\Channels\Microsoft-Windows-TaskScheduler/Operational -Name "ChannelAccess"
-Value "O:SYG:SYD:(D;;0x1;;;WD)"
Restart-Service -Name EventLog -Force -ErrorAction Ignore}
```

Sysmon ID 13 (registry value set) records the actual write:
- `TargetObject: HKLM\SOFTWARE\...\WINEVT\Channels\Microsoft-Windows-TaskScheduler/Operational\ChannelAccess`
- `Details: O:SYG:SYD:(D;;0x1;;;WD)`

Following the service restart, the dataset captures svchost.exe (Event Log service) relaunching
(`svchost.exe -k LocalServiceNetworkRestricted -p -s EventLog`) and file activity on
`C:\Windows\ServiceState\EventLog\Data\lastalive0.dat` and `lastalive1.dat` — evidence that the
Event Log service restarted.

**Security (22 events):** Includes 4688/4689 process creation and termination for PowerShell and
the Event Log svchost restart. Event ID 1100 (event logging service shut down) is present,
directly confirming the service restart. A 4624/4627/4672 SYSTEM logon cluster accompanies the
svchost restart. Token adjustment (4703) for the PowerShell process is also recorded.

**PowerShell (40 events):** Script block logging (4104) captures both the wrapper form
(`& {Set-ItemProperty ... Restart-Service ...}`) and the unwrapped body. Module logging (4103)
records individual cmdlet calls: `Set-ItemProperty` with the exact path, name, and SDDL value,
followed by `Restart-Service -Name EventLog -Force`. The test framework boilerplate includes repeated
`Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass` invocations and a run-time
profile at `C:\Windows\system32\config\systemprofile\Documents\WindowsPowerShell\
Microsoft.PowerShell_profile.ps1`.

## What This Dataset Does Not Contain (and Why)

**No Windows Firewall or Security log policy changes.** This test targets only WINEVT channel
access permissions.

**No successful read-access denial confirmation.** The dataset records the registry write and
service restart; it does not include any event proving that a subsequent log reader was denied —
that would require follow-on activity.

**No privileged registry key creation.** The targeted key already exists; only its `ChannelAccess`
value is modified.

**Sysmon ProcessCreate does not appear for all child processes.** The sysmon-modular config uses
include-mode filtering for ProcessCreate. The Event Log svchost restart is captured because it
matches a LOLBin/service pattern, but not all transient processes are logged by Sysmon; Security
4688 provides full coverage.

## Assessment

The test completed successfully. The registry write (`ChannelAccess` SDDL) and the Event Log
service restart are both clearly recorded. Security 1100 confirms the service stopped. The
PowerShell script block and module log entries provide a complete chain from test framework invocation
through cmdlet execution. The dataset is high-quality for this technique.

## Detection Opportunities Present in This Data

- **Sysmon 13:** Registry write to any `HKLM\...\WINEVT\Channels\*\ChannelAccess` key by a
  non-SYSTEM service is highly anomalous and should trigger immediately.
- **Sysmon 1 / Security 4688:** PowerShell launched with `Set-ItemProperty` targeting WINEVT
  Channels in the command line; the full SDDL value `O:SYG:SYD:(D;;0x1` is a reliable indicator.
- **Security 1100:** Event logging service shutdown followed promptly by a 4688 for
  `svchost.exe -k LocalServiceNetworkRestricted -p -s EventLog` is a restart fingerprint.
- **PowerShell 4103/4104:** `Set-ItemProperty` against `HKLM:\SOFTWARE\Microsoft\Windows\
  CurrentVersion\WINEVT\Channels\` paired with `Restart-Service EventLog` in the same script
  block is a strong composite indicator.
- **Correlation:** 4103 `Restart-Service -Name EventLog` + Security 1100 within seconds = highly
  suspicious programmatic restart of the logging subsystem.
