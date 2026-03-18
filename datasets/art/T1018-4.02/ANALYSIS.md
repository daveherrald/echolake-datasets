# T1018-4: Remote System Discovery — Remote System Discovery - ping sweep

## Technique Context

A ping sweep is one of the most elementary forms of network reconnaissance: sequentially probing IP addresses with ICMP echo requests to determine which hosts are alive. Despite its simplicity, it remains widely used by attackers because it requires no third-party tools (Windows includes `ping.exe`), produces no authentication events, and can be scripted with a single `for` loop in cmd.exe. After compromising a host, attackers run ping sweeps to build a map of reachable subnets before more targeted scanning with tools like nmap or built-in Windows discovery commands.

Detection is straightforward at the process creation level: a loop spawning hundreds of short-lived `ping.exe` processes within seconds is unmistakable. The challenge for defenders is scale — 254 process creation events in rapid succession can overwhelm alert systems tuned for individual event detections, making behavioral clustering or rate-based analytics the more practical approach. Endpoint telemetry (EID 4688 or Sysmon EID 1) is typically sufficient; network-layer ICMP visibility is useful but not required when process creation logging is available.

This test uses the cmd.exe `for /l` loop: `for /l %%i in (1,1,254) do ping -n 1 -w 100 192.168.1.%%i`. The `-n 1` flag sends one packet per host and `-w 100` sets a 100ms timeout, allowing the full /24 sweep to complete in approximately 25 seconds (254 × 100ms) when all hosts are unreachable, which is the case here.

## What This Dataset Contains

This is the largest dataset in the T1018 batch by event count: 7,755 total events across six channels, with the Security channel alone generating 7,297 events. The test runs from approximately 22:58:48 through 22:59:16 UTC on 2026-03-14.

The core technique evidence is definitive. Sysmon EID 1 captures the invocation chain: PowerShell (SYSTEM context) → `cmd.exe` with `"cmd.exe" /c for /l %%i in (1,1,254) do ping -n 1 -w 100 192.168.1.%%i` → 254 individual `ping.exe` processes with command lines `ping  -n 1 -w 100 192.168.1.1` through `ping  -n 1 -w 100 192.168.1.254`. Security EID 4688 records the same 254 `PING.EXE` process creations, each from parent `cmd.exe`.

The Security channel's 4,898 EID 4663 events (object access auditing) and 1,632 EID 4907 events (audit policy changes) are the most numerically dominant events and are unrelated to the ping sweep — they reflect Windows security auditing operations running in parallel. The 478 EID 4664 hard-link events are OS servicing. The 260 EID 4688 events include both the ping processes and the surrounding ART test framework activity.

Notably, this dataset adds channels absent in the defended version: a System channel EID 7040 (service state change) and a WMI channel EID 5860. The WMI event records a `Win32_ProcessStartTrace` subscription query watching for `wsmprovhost.exe` (WinRM), registered from PID 6320 under NT AUTHORITY\SYSTEM — this is the ART framework checking for test framework conditions and is present here because without Defender's interference the test infrastructure runs more completely.

PowerShell EID 4103 module logging confirms the sweep completed: `CommandInvocation(Write-Host): "Write-Host"` with `value="DONE"` — the ART cleanup confirmation message. This is visible only in the undefended run; the defended version's EID 4103 module logging was absent because Defender's interference prevented reaching that cleanup point.

## What This Dataset Does Not Contain

No network-layer ICMP telemetry is captured — there are no Sysmon EID 3 network connection events for the PING.EXE processes, which is expected since Sysmon filters network events for PING.EXE. All 254 ping processes exited with status 0x1 (unreachable), so no live hosts were found on the 192.168.1.0/24 range (the test lab uses 192.168.4.0/24). There are no DNS query events (Sysmon EID 22) because ping resolves IPs directly without name resolution when targeting address literals. There are no file output events; the sweep results are not written to disk.

## Assessment

This is an excellent and comprehensive ping sweep dataset. The 254 individual `ping.exe` process creation events with sequential IP addresses across their command lines provide unambiguous ground truth for detection engineering. The volume of concurrent OS activity (4663, 4907, 4664 Security events) provides realistic context for testing detection precision. The EID 4103 `Write-Host "DONE"` confirmation confirms the sweep ran to completion. This dataset is particularly useful for developing and validating behavioral clustering analytics that must identify ping sweeps against a background of ordinary system activity.

Compared to the defended version (286 Sysmon, 538 Security, 54 PowerShell), this undefended dataset is substantially larger due to the full 254-ping execution running to completion and the additional OS auditing activity captured in parallel. The defended run's smaller count suggests Defender either slowed or partially interrupted the sweep.

## Detection Opportunities Present in This Data

1. **Sysmon EID 1 — cmd.exe command line with for loop**: The command `"cmd.exe" /c for /l %%i in (1,1,254) do ping -n 1 -w 100 192.168.1.%%i` contains the complete sweep specification. Matching `for /l` combined with `ping` in a cmd.exe command line is a high-fidelity indicator.

2. **Sysmon EID 1 / EID 4688 — PING.EXE rate detection**: 254 `PING.EXE` process creation events from a single parent `cmd.exe` within approximately 25 seconds. Rate-based analytics detecting more than a threshold (e.g., 10) ping.exe spawns from the same parent within a rolling window would catch this pattern.

3. **Sysmon EID 1 / EID 4688 — sequential IP pattern**: The command line arguments `192.168.1.1`, `192.168.1.2`, ... `192.168.1.254` across successive PING.EXE creates show arithmetic IP progression. Analytics that extract the destination IP from ping command lines and detect sequential patterns in a time window would identify the sweep intent rather than just the process count.

4. **Sysmon EID 1 — execution as SYSTEM from TEMP**: `cmd.exe` and `PING.EXE` running as NT AUTHORITY\SYSTEM from `C:\Windows\Temp\` is anomalous. A baseline of typical PING.EXE launch contexts would make this context highly detectable.

5. **EID 4103 — PowerShell module logging**: The `Write-Host "DONE"` invocation confirms sweep completion and the test framework's execution pattern. This is visible in the full dataset and useful for understanding ART test framework artifacts that should be excluded from technique-specific analytics.

6. **WMI EID 5860 — ProcessStartTrace subscription**: A `Win32_ProcessStartTrace` WMI event subscription watching for `wsmprovhost.exe` being created by NT AUTHORITY\SYSTEM is a living-off-the-land behavioral indicator for process monitoring activity associated with automation frameworks.
