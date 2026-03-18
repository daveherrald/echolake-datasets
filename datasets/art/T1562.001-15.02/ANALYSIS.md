# T1562.001-15: Disable or Modify Tools — Disable Arbitrary Security Windows Service

## Technique Context

T1562.001 (Disable or Modify Tools) includes stopping and permanently disabling Windows services that provide security functions. This test targets `McAfeeDLPAgentService` — the McAfee Data Loss Prevention agent service — using a two-step command:
1. `net.exe stop McAfeeDLPAgentService` — halt the running service
2. `sc.exe config McAfeeDLPAgentService start= disabled` — prevent the service from starting on next boot

The two-step pattern is operationally significant. Stopping a service alone is insufficient: many security services are configured to auto-restart, and a system reboot would re-enable the service. Marking the service as disabled survives reboots and ensures the agent remains inactive until an administrator intervenes. This pattern is generic across any Windows service — the same command structure applies to any security product, AV agent, EDR sensor, or monitoring tool.

This technique appears in intrusions where attackers enumerate installed security products and disable them before executing the primary payload.

## What This Dataset Contains

The dataset spans 5 seconds (2026-03-17 17:34:45–17:34:50 UTC) and contains 53 PowerShell events, 11 Security events, 1 System event, 1 Application event, and 1 WMI event.

The service disruption command is captured in Security EID 4688:
```
"cmd.exe" /c net.exe stop McAfeeDLPAgentService & sc.exe config McAfeeDLPAgentService start= disabled
```

Security EID 4688 records 7 process creation events:
- `C:\Windows\System32\svchost.exe -k netsvcs -p -s BITS` — BITS service host (unrelated OS activity)
- `whoami.exe` (pre-check)
- `cmd.exe /c net.exe stop McAfeeDLPAgentService & sc.exe config McAfeeDLPAgentService start= disabled`
- `net.exe  stop McAfeeDLPAgentService`
- `C:\Windows\system32\net1  stop McAfeeDLPAgentService`
- `sc.exe  config McAfeeDLPAgentService start= disabled`
- Second `whoami.exe` (post-check)

The `net1.exe` entry is a standard Windows artifact: `net.exe` delegates its actual service operations to `net1.exe`, its subprocess. Both appear as separate process creation events.

**Security EID 4624** records a successful logon with Logon Type 5 (service logon) for `ACME-WS06$` as SYSTEM — reflecting the BITS service host initialization.

**Security EID 4672** records special privileges assigned to the SYSTEM account logon, showing `SeAssignPrimaryTokenPrivilege`, `SeTcbPrivilege`, `SeSecurityPrivilege`, `SeTakeOwnershipPrivilege`, `SeLoadDriverPrivilege`, and others — the standard SYSTEM privilege set.

**Security EID 4799** records security-enabled local group membership enumeration twice: once for `Administrators` (S-1-5-32-544) and once for `Backup Operators` (S-1-5-32-551). These enumerations are triggered by the BITS service initialization, not by the attack command.

**System EID 7040** records: `The start type of the Background Intelligent Transfer Service service was changed from demand start to auto start` — BITS service configuration change, unrelated OS activity captured in the 5-second collection window.

**WMI EID 5860** records a WMI notification query: `SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName = 'wsmprovhost.exe'` — the ART test framework's WinRM host detection query, a standard test framework artifact.

**Application EID 15** records `Updated Windows Defender status successfully to SECURITY_PRODUCT_STATE_ON` — Defender status update, consistent with background security center activity.

The 53 PowerShell events are all EID 4104 script block logging containing ART boilerplate only — no technique-specific content appears in PowerShell logs because the attack operates via `cmd.exe`/`net.exe`/`sc.exe` child processes, not PowerShell cmdlets.

## What This Dataset Does Not Contain

No evidence that McAfeeDLPAgentService exists on this host. The service is not installed on ACME-WS06. The `net.exe stop` command returned an error (the service does not exist), and `sc.exe config` attempted to modify a service entry that was absent. No Service Control Manager events (System EID 7034/7035/7036) appear for McAfeeDLPAgentService because there is nothing to stop.

No Sysmon events. Similar to T1562.001-13 and T1562.001-14, the Sysmon channel is absent here. This run cluster (17:34:xx UTC) falls after the Sysmon driver unload in T1562.001-11, suggesting the driver may still have been in a degraded state during these subsequent tests. All process creation evidence comes from Security EID 4688.

No sc.exe exit code confirmation. Without Sysmon EID 1 or Security EID 4689, the outcome of the `sc.exe config` command cannot be confirmed from process exit codes alone. The command structure is present; success or failure must be inferred from the absence of Service Control Manager events.

Compared to the defended variant (29 Sysmon, 16 Security, 34 PowerShell), the undefended run has no Sysmon events and slightly more Security events (11 vs 16) and more PowerShell events (53 vs 34). The additional Security events here include the BITS-related EID 4624/4672/4799 cluster that was also present in the defended variant.

## Assessment

This dataset captures the attempt to disable a security service that is not installed on the host. The command line evidence is complete and unambiguous — the stop-and-disable pattern targeting McAfeeDLPAgentService is fully recorded in Security EID 4688. The technique fails due to a prerequisite absence, not a security control block.

The operational significance extends beyond the specific service name. An attacker who attempts to stop and disable McAfeeDLPAgentService is running reconnaissance-and-disable commands without confirming the service exists first. In a real intrusion, this pattern might reflect a toolkit that tries to disable a predefined list of security products regardless of what is installed. Detection logic should focus on the command structure and service names, not on whether the target service is present.

The additional Security events (BITS, SYSTEM logon, group enumeration) demonstrate that even a short collection window on a real Windows endpoint captures ambient OS activity. These events are not related to the attack but would appear in any analyst's dataset from this time window.

## Detection Opportunities Present in This Data

**Security EID 4688 for the combined `net.exe` / `sc.exe` command**: `"cmd.exe" /c net.exe stop McAfeeDLPAgentService & sc.exe config McAfeeDLPAgentService start= disabled` in a single command line, spawned from SYSTEM PowerShell, is the primary indicator. The combination of `net stop` and `sc config start= disabled` for the same service name in a chained command is a documented pattern in intrusion playbooks.

**Security EID 4688 for `net1.exe`**: `net1.exe` appearing as a child of `net.exe` with a service name argument is a standard Windows artifact, but its appearance in the context of security service disruption is worth logging. `net1.exe` with service names as arguments is unusual in normal endpoint operations.

**Security EID 4688 for `sc.exe config ... start= disabled`**: The `sc.exe config` command with `start= disabled` targeting any service is a meaningful event on its own. Disabling services via `sc.exe` is low-frequency in normal operations and high-frequency in intrusions. A detect-on-behavior approach that monitors for `sc.exe config` with `start= disabled` arguments will catch this pattern regardless of the targeted service name.

**Process chain**: `powershell.exe` (SYSTEM) → `cmd.exe` (combined net/sc command) → `net.exe` → `net1.exe` and `sc.exe` in parallel — this chain is visible in Security 4688 parent-child relationships. The full execution tree is reconstructable from these events.
