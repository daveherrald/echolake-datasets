# T1562.001-15: Disable or Modify Tools — Disable Arbitrary Security Windows Service

## Technique Context

T1562.001 (Disable or Modify Tools) includes stopping and disabling security software services using built-in Windows service control utilities. This test targets `McAfeeDLPAgentService` — a McAfee Data Loss Prevention agent service — using `net.exe stop` to halt the running service and `sc.exe config ... start= disabled` to prevent it from restarting. This two-step pattern (stop then disable) is operationally significant: stopping alone is insufficient because the service may auto-restart, while disabling ensures it remains inactive across reboots. This approach works against any Windows service regardless of vendor, making the technique highly generic.

## What This Dataset Contains

The dataset captures 79 events across Sysmon, Security, and PowerShell logs collected during a 5-second window on 2026-03-14 at 14:49 UTC.

The service disruption command is visible in multiple log sources:

```
"cmd.exe" /c net.exe stop McAfeeDLPAgentService & sc.exe config McAfeeDLPAgentService start= disabled
```

Key observations from the data:

- **Sysmon EID 1** fires for five process creations: `whoami.exe` (T1033), `cmd.exe` (T1059.003 — Windows Command Shell), `net.exe` (T1018 — Remote System Discovery, a sysmon-modular annotation applied to net.exe calls), `net1.exe` (T1018, spawned by net.exe as its subprocess), and `sc.exe` (T1543.003 — Windows Service rule).
- **Sysmon EID 1 for `cmd.exe`**: Full command line `"cmd.exe" /c net.exe stop McAfeeDLPAgentService & sc.exe config McAfeeDLPAgentService start= disabled` with parent `powershell.exe` as SYSTEM.
- **Sysmon EID 1 for `net.exe`**: `net.exe  stop McAfeeDLPAgentService` with parent `cmd.exe`.
- **Sysmon EID 1 for `net1.exe`**: `C:\Windows\system32\net1  stop McAfeeDLPAgentService` — net1.exe is the actual binary that net.exe delegates service operations to; its appearance here is a standard Windows behavior artifact.
- **Sysmon EID 1 for `sc.exe`**: `sc.exe  config McAfeeDLPAgentService start= disabled` with parent `cmd.exe` and hash values.
- Security EID 4688 records all three key process creations (`cmd.exe`, `net.exe`, `net1.exe`, `sc.exe`) with full command lines.
- Security EID 4703 records token right adjustments for the SYSTEM process.
- Sysmon EID 7, 10, 11, 17 are standard PowerShell test framework artifacts.
- PowerShell EID 4104 and 4103 contain only ART boilerplate.

The `McAfeeDLPAgentService` is not installed on ACME-WS02, so `net.exe stop` returns an error (the service does not exist), but the `sc.exe config` attempt still executes. This means the dataset shows the attempt even though the targeted service is absent — a realistic scenario where adversaries run service-disabling commands without prior enumeration.

## What This Dataset Does Not Contain (and Why)

**No evidence of McAfeeDLPAgentService being present or running.** The service does not exist on this host. The dataset captures the stop and disable attempts but not a successful service stop event (e.g., System log service control events).

**No System log service events.** Service start/stop events (System EID 7034, 7036) are not present because the service does not exist. Object access auditing is also not enabled.

**No Defender block.** Running as SYSTEM, Defender does not block net.exe or sc.exe from making service control calls, even to non-existent services.

**No registry modification for service start type.** The `sc.exe config ... start= disabled` command modifies the service's registry entry, but Sysmon RegistryEvent rules do not capture this specific path.

## Assessment

This dataset is notable for capturing the complete process chain for a service-disabling operation with excellent Sysmon coverage. All five relevant processes appear in Sysmon EID 1 with full command lines, hashes, and parent-child relationships. The net1.exe subprocess artifact provides a characteristic fingerprint: any `net.exe stop <service>` invocation will produce a corresponding `net1.exe  stop <service>` event that can be used for correlation. The sc.exe `start= disabled` pattern (note the space before `disabled`, which is a quirk of the sc.exe syntax) is itself a distinctive indicator. The fact that McAfeeDLPAgentService is absent does not affect detection quality — the command-line evidence is present regardless of outcome.

## Detection Opportunities Present in This Data

- **Sysmon EID 1**: `cmd.exe` with `net.exe stop <security-service>` and `sc.exe config <security-service> start= disabled` in command line, spawned by PowerShell as SYSTEM.
- **Sysmon EID 1**: `sc.exe` with `config <service-name> start= disabled` command line, particularly for known security product service names.
- **Sysmon EID 1**: `net1.exe` with `stop <service-name>` — the net1.exe delegation pattern is a reliable secondary indicator for net.exe service stop operations.
- **Security EID 4688**: Full command line for `cmd.exe` showing the stop-then-disable pattern in a single command chain — provides detection without Sysmon.
- **Service name matching**: Commands referencing security vendor service names (McAfee, CrowdStrike, Carbon Black, Symantec, etc.) in `net stop` or `sc config ... disabled` contexts.
- **Behavioral pattern**: Stop-then-disable in a single cmd.exe invocation as SYSTEM indicates deliberate service disruption rather than incidental administration.
