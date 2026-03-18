# T1562.004-1: Disable or Modify System Firewall — Disable Microsoft Defender Firewall

## Technique Context

T1562.004 covers disabling or modifying the host firewall to permit unrestricted network access.
Test 1 uses the canonical Windows Firewall management command:
`netsh advfirewall set currentprofile state off`
This disables all firewall profiles that apply to the current network connection, removing all
inbound and outbound filtering. It is one of the most commonly observed firewall-disabling
commands in ransomware and post-exploitation toolkits. Execution is via cmd.exe as SYSTEM.

## What This Dataset Contains

**Sysmon (84 events):** The richest sysmon dataset in this group. Sysmon ID 1 captures the
complete attack chain:

- `whoami.exe` — ART test framework identity check (RuleName: T1033)
- `cmd.exe /c netsh advfirewall set currentprofile state off` (RuleName: T1518.001)
- `netsh.exe advfirewall set currentprofile state off` (RuleName: T1518.001)

Sysmon ID 13 records the downstream registry effect — svchost (SharedAccess/Windows Firewall
service) writing the result:
- `HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\EnableFirewall`
- `Details: DWORD (0x00000000)`

Sysmon 12 (registry object create/delete) events also appear, reflecting Windows Firewall's
internal state management. Sysmon 7 (image loads for PowerShell and Defender DLLs including
`MpOAV.dll`, `MpClient.dll`), 10 (process access), 11 (file create), and 17 (named pipe) round
out the picture.

**Security (20 events):** 4688/4689 for the full process chain including netsh.exe. A 4624/4627/
4672 SYSTEM logon cluster is present, reflecting scheduled task or service-initiated execution.
Token adjustment (4703) for the PowerShell test framework.

**Application (1 event):** Event ID 16394 — "Offline downlevel migration succeeded" — a benign
Windows Update housekeeping event coincident with the collection window.

**WMI (1 event):** ID 5858 — WMI query failure for Delivery Optimization monitoring. Ambient
OS activity.

**TaskScheduler (9 events):** Windows Update Orchestrator and OneSettings tasks running
concurrently. These reflect real-world OS background activity, not the attack.

**PowerShell (34 events):** ART test framework boilerplate only — `Set-ExecutionPolicy Bypass` and
error-handling fragments. The attack itself uses cmd.exe/netsh, so no technique-specific
PowerShell cmdlets appear.

## What This Dataset Does Not Contain (and Why)

**No Windows Firewall Operational log events.** The collection channels do not include
`Microsoft-Windows-Windows Firewall With Advanced Security/Firewall`. Firewall-specific events
(e.g., event 2003 — firewall setting changed) would appear there but are not collected.

**No confirmation of all-profile disablement.** `currentprofile` targets the active profile.
Events for `StandardProfile` and `PrivateProfile` would require separate registry keys, which
are not explicitly written here.

**No network connection change.** The dataset captures the firewall disable action; it does not
include any subsequent inbound connection that exploited the open state.

**Sysmon ProcessCreate filtering:** Many background processes visible in Security 4688 are not
in Sysmon 1. The task scheduler and Windows Update processes are absent from Sysmon.

## Assessment

The test completed successfully. The netsh command line and the downstream `EnableFirewall=0`
registry write are clearly captured. The additional telemetry sources (application, WMI, task
scheduler) provide authentic environmental context reflecting a live Windows 11 domain workstation.

## Detection Opportunities Present in This Data

- **Sysmon 1 / Security 4688:** `netsh.exe` with arguments `advfirewall set currentprofile state off`
  (or any profile variant) is a reliable, high-fidelity indicator.
- **Sysmon 13:** `EnableFirewall` DWORD written to 0 in any `FirewallPolicy\*Profile` key by
  svchost (reflecting netsh's effect) — correlate with the netsh execution.
- **Sysmon 12:** Firewall registry key deletions or object creation in `SharedAccess\Parameters`
  are abnormal outside Group Policy application.
- **Security 4688:** cmd.exe spawning netsh.exe with firewall-disabling arguments detectable
  without Sysmon.
- **Parent process:** The PowerShell test framework spawning cmd.exe which spawns netsh.exe is a
  process lineage worth encoding — legitimate firewall changes are typically made by management
  tools or services, not user-launched PowerShell.
